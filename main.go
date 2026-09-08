package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"log/slog"
	"synapse/internal/alerts"
	"synapse/internal/auth"
	"synapse/internal/authelia"
	"synapse/internal/db"
	"synapse/internal/docker"
	"synapse/internal/kuma"
	"synapse/internal/logging"
	"synapse/internal/notify"
	"synapse/internal/notify/channels"
	"synapse/internal/npm"
	synclib "synapse/internal/sync"
	"synapse/internal/telemetry"
)

var version = "1.30.0"

type sessionInfo struct {
	Expiry time.Time
	UserID int64
	// OIDC marks sessions created via Authelia OIDC login (vs local password).
	// Mutation auth accepts a valid OIDC session alone; local sessions still
	// require a bearer token on top. Email/Groups come from verified ID claims.
	// ponytail: subject/groups live in the session, not new DB columns.
	OIDC   bool
	Email  string
	Groups []string
}

var (
	sessionStore   = make(map[string]sessionInfo)
	sessionStoreMu sync.RWMutex
)

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func setSessionCookie(c *gin.Context, id string) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("session", id, 86400, "/", "", false, true)
}

func cleanupSessions() {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()
	now := time.Now()
	for id, s := range sessionStore {
		if now.After(s.Expiry) {
			delete(sessionStore, id)
		}
	}
}

func (app *App) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if sessionID, err := c.Cookie("session"); err == nil && sessionID != "" {
			sessionStoreMu.Lock()
			s, ok := sessionStore[sessionID]
			if ok && time.Now().After(s.Expiry) {
				delete(sessionStore, sessionID)
				ok = false
			}
			sessionStoreMu.Unlock()
			if ok {
				c.Set("user_id", s.UserID)
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
			return
		}
		// OIDC on: a valid service-account bearer also satisfies the outer
		// group (automation + NPM forward-auth bypass without a session).
		// Reads stay session-or-token; mutations enforce their own OR rule.
		// OIDC off: behavior unchanged (session required).
		if app.oidcEnabled() {
			if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				if secret := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); secret != "" {
					if token, err := app.database.GetAPITokenByHash(hashToken(secret)); err == nil && token != nil &&
						token.RevokedAt == nil && (token.ExpiresAt == nil || time.Now().Before(*token.ExpiresAt)) {
						c.Set("api_token_id", token.ID)
						c.Set("api_token_owner_id", token.OwnerID)
						c.Set("user_id", token.OwnerID)
						_ = app.database.TouchAPIToken(token.ID)
						c.Next()
						return
					}
				}
			}
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
	}
}

// generateAPIToken returns a new 64-character hex bearer secret (32 random
// bytes). Only its SHA-256 hash is persisted; the plaintext is returned to the
// caller exactly once.
func generateAPIToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// oidcEnabled reports whether Authelia OIDC login is configured.
func (app *App) oidcEnabled() bool {
	return app.oidcCfg.Enabled()
}

// initOIDC discovers the Authelia OIDC provider and builds the verifier.
// Returns nil (disabled) when OIDC_CLIENT_ID is unset — local auth is then
// unchanged. Discovery failure returns an error but must not crash startup;
// callers check app.oidcProvider != nil before serving OIDC routes.
func (app *App) initOIDC(ctx context.Context) error {
	app.oidcCfg = auth.LoadFromEnv()
	if !app.oidcCfg.Enabled() {
		slog.Info("oidc disabled (OIDC_CLIENT_ID unset) — local auth only")
		return nil
	}
	provider, err := oidc.NewProvider(ctx, app.oidcCfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery %s: %w", app.oidcCfg.Issuer, err)
	}
	app.oidcProvider = provider
	app.oidcVerifier = provider.Verifier(&oidc.Config{ClientID: app.oidcCfg.ClientID})
	app.oauth2Cfg = &oauth2.Config{
		ClientID:     app.oidcCfg.ClientID,
		ClientSecret: app.oidcCfg.ClientSecret,
		RedirectURL:  app.oidcCfg.RedirectURL,
		Scopes:       app.oidcCfg.Scopes,
		Endpoint:     provider.Endpoint(),
	}
	slog.Info("oidc enabled", "issuer", app.oidcCfg.Issuer)
	return nil
}

// mutationAuthMiddleware enforces the OIDC OR rule for state-changing routes:
// a valid OIDC session alone suffices, and a valid service-account bearer
// token alone suffices (automation + NPM forward-auth bypass). A valid local
// (password) session alone is NOT sufficient — it still needs a bearer token,
// preserving the pre-OIDC secure-api-mutations behavior.
// Only registered when OIDC is enabled; otherwise the legacy
// authMiddleware()+bearerTokenMiddleware() chain applies.
func (app *App) mutationAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Outer authMiddleware already validated a bearer (set when OIDC is
		// on and the request carried a valid token without a session).
		if _, ok := c.Get("api_token_id"); ok {
			c.Next()
			return
		}
		var sessionUser int64
		if sid, err := c.Cookie("session"); err == nil && sid != "" {
			sessionStoreMu.Lock()
			s, ok := sessionStore[sid]
			if ok && time.Now().After(s.Expiry) {
				delete(sessionStore, sid)
				ok = false
			}
			sessionStoreMu.Unlock()
			if ok {
				sessionUser = s.UserID
				c.Set("user_id", s.UserID)
				if s.OIDC {
					c.Next()
					return
				}
			}
		}
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			if secret := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); secret != "" {
				if token, err := app.database.GetAPITokenByHash(hashToken(secret)); err == nil && token != nil &&
					token.RevokedAt == nil && (token.ExpiresAt == nil || time.Now().Before(*token.ExpiresAt)) {
					c.Set("api_token_id", token.ID)
					c.Set("api_token_owner_id", token.OwnerID)
					if sessionUser == 0 {
						c.Set("user_id", token.OwnerID)
					}
					_ = app.database.TouchAPIToken(token.ID)
					c.Next()
					return
				}
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
				return
			}
		}
		if sessionUser != 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
	}
}

// useMutationAuth attaches mutation protection: legacy session+bearer chain
// when OIDC is off, OR middleware when on. Call for the mut subgroup.
func (app *App) useMutationAuth(mut *gin.RouterGroup) {
	if app.oidcEnabled() {
		mut.Use(app.mutationAuthMiddleware())
		return
	}
	mut.Use(app.bearerTokenMiddleware())
}

// registerOIDCRoutes adds login/callback/status. Safe to call when disabled —
// handlers return 404/503 then. Shared by main router and test router.
func (app *App) registerOIDCRoutes(r *gin.Engine) {
	r.GET("/api/auth/oidc/login", app.HandleOIDCLogin)
	r.GET("/api/auth/oidc/callback", app.HandleOIDCCallback)
	r.GET("/api/auth/oidc/status", app.HandleOIDCStatus)
}
// token on top of the session authentication applied by authMiddleware. It
// stores the token id and owner id in the gin context for handlers that need
// them. Failure aborts with 401 before any handler runs, so no write can occur.
func (app *App) bearerTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		secret := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if secret == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		token, err := app.database.GetAPITokenByHash(hashToken(secret))
		if err != nil || token == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
			return
		}
		if token.RevokedAt != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
			return
		}
		if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
			return
		}
		c.Set("api_token_id", token.ID)
		c.Set("api_token_owner_id", token.OwnerID)
		// Best-effort last-used tracking; never fail the request on a write error.
		_ = app.database.TouchAPIToken(token.ID)
		c.Next()
	}
}

type App struct {
	database     *db.DB
	kumaRegistry *kuma.Registry
	npmRegistry  *npm.Registry
	dockerClient *docker.Client

	// OIDC (Authelia) login. Zero value = disabled; local auth unchanged.
	oidcCfg      auth.Config
	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
	oauth2Cfg    *oauth2.Config

	mu            sync.Mutex
	running       bool
	progressChans []chan synclib.Progress
}

func (app *App) settings() db.Settings {
	return app.database.GetSettings(db.Settings{
		ComposePath:               getEnv("COMPOSE_PATH", "docker-compose.yml"),
		NPMHost:                   getEnv("NPM_HOST", "http://nginx:81"),
		NPMUser:                   getEnv("NPM_USER", "admin"),
		NPMPass:                   getEnv("NPM_PASS", ""),
		KumaURL:                   getEnv("KUMA_URL", "http://uptime-kuma:3001"),
		KumaUser:                  getEnv("KUMA_USER", "admin"),
		KumaPass:                  getEnv("KUMA_PASS", ""),
		AutheliaConfigPath:        getEnv("AUTHELIA_CONFIG_PATH", ""),
		AutheliaDBPath:            getEnv("AUTHELIA_DB_PATH", ""),
		AutheliaSyncEnabled:       getEnv("AUTHELIA_SYNC_ENABLED", "") == "true",
		AutheliaDefaultPolicy:     getEnv("AUTHELIA_DEFAULT_POLICY", authelia.DefaultPolicy),
		OTelEndpoint:              getEnv("OTEL_ENDPOINT", ""),
		OTelEnabled:               getEnv("OTEL_ENABLED", "") == "true",
		EinkEnabled:               getEnv("EINK_ENABLED", "") == "true",
		TrmnlApiToken:             getEnv("TRMNL_API_TOKEN", ""),
		NotifyEnabled:             getEnv("NOTIFY_ENABLED", "") == "true",
		NotifyIntervalMinutes:     getEnvInt("NOTIFY_INTERVAL_MINUTES", 60),
		GotifyURL:                 getEnv("GOTIFY_URL", ""),
		GotifyToken:               getEnv("GOTIFY_TOKEN", ""),
		GotifyPriority:            getEnvInt("GOTIFY_PRIORITY", 5),
		DockerSocket:              getEnv("DOCKER_SOCKET", ""),
		DockerEventsEnabled:       getEnv("DOCKER_EVENTS_ENABLED", "") == "true",
		DockerEventsRetentionDays: getEnvInt("DOCKER_EVENTS_RETENTION_DAYS", 30),
		ReconcileEnabled:          getEnv("RECONCILE_ENABLED", "") == "true",
		ReconcileIntervalMinutes:  getEnvInt("RECONCILE_INTERVAL_MINUTES", 60),
		ReconcileDryRunDefault:    getEnv("RECONCILE_DRY_RUN_DEFAULT", "true") == "true",
		NotifyDockerDie:           getEnv("NOTIFY_DOCKER_DIE", "") == "true",
		NotifyDockerHealth:        getEnv("NOTIFY_DOCKER_HEALTH", "") == "true",
		NotifyDockerImage:         getEnv("NOTIFY_DOCKER_IMAGE", "") == "true",
		NotifyReconcile:           getEnv("NOTIFY_RECONCILE", "") == "true",
		NotifyAlerts:              getEnv("NOTIFY_ALERTS", "") == "true",
		NotifyCooldownMinutes:     getEnvInt("NOTIFY_COOLDOWN_MINUTES", 5),
		NotifyPersistent:          getEnv("NOTIFY_PERSISTENT", "") == "true",
		AlertsEnabled:             getEnv("ALERTS_ENABLED", "") == "true",
		AlertEvalIntervalSeconds:  getEnvInt("ALERT_EVAL_INTERVAL_SECONDS", 60),
		AlertReminderMinutes:      getEnvInt("ALERT_REMINDER_MINUTES", 0),
		KumaDefaultTags:           getEnv("KUMA_DEFAULT_TAGS", ""),
	})
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func mask(s string) string {
	if s == "" {
		return ""
	}
	return "****"
}

// maskChannelsDoc masks per-channel tokens in a notify_channels JSON document
// before it is returned to the settings page. Invalid documents pass through
// unchanged (the save path rejects them anyway).
func maskChannelsDoc(doc string) string {
	doc = strings.TrimSpace(doc)
	if doc == "" {
		return ""
	}
	cfgs, err := channels.ParseChannels(doc)
	if err != nil {
		return doc
	}
	for i := range cfgs {
		if cfgs[i].Token != "" {
			cfgs[i].Token = "****"
		}
	}
	out, err := json.Marshal(cfgs)
	if err != nil {
		return doc
	}
	return string(out)
}

func main() {
	logging.Init()

	dbPath := getEnv("DB_PATH", "/db/synapse.db")
	addr := getEnv("LISTEN_ADDR", ":6270")

	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	// Migrate legacy single-instance kuma_* settings into KumaInstance rows.
	legacySettings := db.Settings{
		KumaURL:  getEnv("KUMA_URL", "http://uptime-kuma:3001"),
		KumaUser: getEnv("KUMA_USER", "admin"),
		KumaPass: getEnv("KUMA_PASS", ""),
	}
	// Read persisted legacy settings (override env defaults if present).
	persisted := database.GetSettings(legacySettings)
	legacySettings.KumaURL = persisted.KumaURL
	legacySettings.KumaUser = persisted.KumaUser
	legacySettings.KumaPass = persisted.KumaPass
	if err := database.MigrateKumaInstances(legacySettings); err != nil {
		slog.Warn("kuma instance migration failed", "error", err)
	}
	if err := database.MigrateNPMInstances(legacySettings); err != nil {
		slog.Warn("npm instance migration failed", "error", err)
	}
	// Migrate the legacy TRMNL placeholder token into the API token store.
	if err := database.MigrateTrmnlToken(); err != nil {
		slog.Warn("trmnl token migration failed", "error", err)
	}

	app := &App{
		database:     database,
		kumaRegistry: kuma.NewRegistry(database),
		npmRegistry:  npm.NewRegistry(database),
	}

	// Connect to the Docker Engine (graceful when the socket is unavailable —
	// event tracking and container state enrichment degrade to disabled).
	if sock := getEnv("DOCKER_SOCKET", ""); sock != "" {
		dc, err := docker.New(sock)
		if err == nil {
			pingCtx, pingCancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = dc.Ping(pingCtx)
			pingCancel()
			if err != nil {
				dc = nil
			}
		}
		if dc == nil {
			slog.Warn("docker engine unreachable — event tracking and container state disabled", "socket", sock, "error", err)
		} else {
			app.dockerClient = dc
			slog.Info("docker engine connected", "socket", sock)
		}
	}

	// Read OTel endpoint from database settings, fall back to env var
	otelSettings := app.settings()
	otelEndpoint := ""
	if otelSettings.OTelEnabled {
		otelEndpoint = otelSettings.OTelEndpoint
	}

	providers, err := telemetry.InitTelemetry(otelEndpoint)
	if err != nil {
		slog.Warn("telemetry initialization failed, continuing without tracing", "error", err)
		providers = nil
	}
	defer telemetry.Shutdown(providers)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Authelia OIDC discovery (disabled when OIDC_CLIENT_ID is unset).
	// Discovery failure warns but does not crash; OIDC routes then 404/503.
	if err := app.initOIDC(ctx); err != nil {
		slog.Warn("oidc init failed — OIDC login unavailable", "error", err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.SetTrustedProxies(nil)

	r.Use(otelgin.Middleware("synapse"))
	r.Use(telemetry.MetricsMiddleware())

	// Compress responses (HTML, JS, CSS, JSON) on the fly. The SSE progress
	// stream is excluded — compressing it breaks streaming proxies.
	r.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithExcludedPaths([]string{"/api/sync/progress"})))

	// Allow the browser to cache built assets (static/dist) for an hour;
	// index.html is revalidated via no-cache in the Dashboard handler.
	r.Use(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/dist/") || strings.HasPrefix(p, "/static/") {
			c.Header("Cache-Control", "public, max-age=3600")
		}
		c.Next()
	})

	r.LoadHTMLGlob("static/*.html")
	r.Static("/dist", "./static/dist")

	r.GET("/", app.Dashboard)
	r.GET("/setup", func(c *gin.Context) {
		count, _ := app.database.CountAdminUsers()
		if count > 0 {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "setup.html", nil)
	})
	r.GET("/login", func(c *gin.Context) {
		sessionID, err := c.Cookie("session")
		if err == nil && sessionID != "" {
			sessionStoreMu.RLock()
			s, ok := sessionStore[sessionID]
			sessionStoreMu.RUnlock()
			if ok && time.Now().Before(s.Expiry) {
				c.Redirect(http.StatusFound, "/")
				return
			}
		}
		count, _ := app.database.CountAdminUsers()
		if count == 0 {
			c.Redirect(http.StatusFound, "/setup")
			return
		}
		c.HTML(http.StatusOK, "login.html", nil)
	})
	r.GET("/static/*filepath", func(c *gin.Context) {
		c.File("static/" + c.Param("filepath"))
	})

	// Public board — Homer-like overview of all running services (no auth)
	r.GET("/overview", app.OverviewPage)
	r.GET("/board", app.OverviewPage)
	r.GET("/api/public/overview", app.PublicOverview)

	r.GET("/api/check-setup", app.HandleCheckSetup)
	r.POST("/api/login", app.HandleLogin)
	app.registerOIDCRoutes(r)

	// Public v1 API group. TRMNL devices poll /trmnl/stats without a session;
	// the handler performs its own token verification.
	apiV1 := r.Group("/api/v1")
	{
		// Public read-only integration endpoint for TRMNL devices. Per spec
		// (api-authentication), this stays fully unauthenticated.
		apiV1.GET("/trmnl/stats", app.TrmnlStats)
	}

	api := r.Group("/api")
	api.Use(app.authMiddleware())
	{
		// Session-only routes: reads, logout, and token lifecycle. Token
		// lifecycle is the bootstrap path — a token cannot be required to
		// create the first token — and is owner-scoped to the session user.
		api.POST("/logout", app.HandleLogout)
		api.GET("/settings", app.GetSettings)
		api.GET("/status", app.Status)
		api.GET("/sync/progress", app.ProgressSSE)
		api.GET("/sync/history", app.SyncHistory)
		api.GET("/reconcile/runs", app.ReconcileRuns)
		api.GET("/docker/events", app.DockerEvents)
		api.GET("/events", app.EventsFeed)
		api.GET("/services", app.Services)
		api.GET("/proxies", app.Proxies)
		api.GET("/monitors", app.KumaMonitors)
		api.GET("/monitors/:id/stats", app.KumaMonitorStats)
		api.GET("/npm/proxy-hosts", app.NPMProxyHosts)
		api.GET("/service-links", app.ServiceLinks)
		api.GET("/notify/missing", app.NotifyMissing)
		api.GET("/logs", app.LogsHandler)
		api.GET("/logs/stream", app.LogsStreamSSE)
		api.GET("/authelia/status", app.AutheliaStatus)
		api.GET("/authelia/coverage", app.AutheliaCoverage)
		api.GET("/authelia/alerts", app.AutheliaAlerts)
		api.GET("/authelia/temp-access", app.AutheliaTempAccess)
		api.GET("/authelia-instances", app.ListAutheliaInstances)
		api.GET("/kuma-instances", app.ListKumaInstances)
		api.GET("/npm-instances", app.ListNPMInstances)
		api.GET("/alert-rules", app.AlertRules)
		api.GET("/incidents", app.Incidents)

		// Token lifecycle (session-only, owner-scoped)
		api.POST("/tokens", app.CreateToken)
		api.GET("/tokens", app.ListTokens)
		api.POST("/tokens/:id/revoke", app.RevokeToken)
		api.POST("/tokens/:id/rotate", app.RotateToken)

		// Mutation subgroup: every state-changing route below requires auth.
		// OIDC off: session AND bearer token (secure-api-mutations).
		// OIDC on: valid OIDC session OR valid bearer token (automation +
		// NPM forward-auth bypass for Bearer calls). Future mutation routes
		// MUST be registered here so the protection cannot be omitted.
		mut := api.Group("")
		app.useMutationAuth(mut)
		{
			mut.POST("/settings", app.SaveSettings)
			mut.POST("/test/npm", app.TestNPM)
			mut.POST("/kuma-instances", app.CreateKumaInstance)
			mut.PUT("/kuma-instances/:id", app.UpdateKumaInstance)
			mut.DELETE("/kuma-instances/:id", app.DeleteKumaInstance)
			mut.POST("/kuma-instances/:id/test", app.TestKumaInstance)
			mut.POST("/npm-instances", app.CreateNPMInstance)
			mut.PUT("/npm-instances/:id", app.UpdateNPMInstance)
			mut.DELETE("/npm-instances/:id", app.DeleteNPMInstance)
			mut.POST("/npm-instances/:id/test", app.TestNPMInstance)
			mut.POST("/sync/docker", app.DockerSync)
			mut.POST("/sync/npm", app.NPMSync)
			mut.POST("/reconcile", app.Reconcile)
			mut.POST("/monitors", app.CreateKumaMonitor)
			mut.PUT("/monitors/:kumaId", app.UpdateKumaMonitor)
			mut.DELETE("/monitors/:kumaId", app.DeleteKumaMonitor)
			mut.POST("/monitors/:kumaId/pause", app.PauseKumaMonitor)
			mut.POST("/monitors/:kumaId/resume", app.ResumeKumaMonitor)
			mut.PUT("/monitors/:kumaId/tags", app.SetMonitorTags)
			mut.POST("/npm/proxy-hosts", app.CreateNPMProxyHost)
			mut.PUT("/npm/proxy-hosts/:id", app.UpdateNPMProxyHost)
			mut.POST("/service-links", app.CreateServiceLink)
			mut.PUT("/service-links/:id", app.UpdateServiceLink)
			mut.DELETE("/service-links/:id", app.DeleteServiceLink)
			mut.POST("/service-links/:id/refresh", app.RefreshServiceLink)
			mut.POST("/notify/test", app.NotifyTest)
			mut.POST("/alert-rules", app.CreateAlertRule)
			mut.PUT("/alert-rules/:id", app.UpdateAlertRule)
			mut.DELETE("/alert-rules/:id", app.DeleteAlertRule)
			mut.POST("/incidents/:id/ack", app.AckIncident)
			mut.POST("/incidents/:id/resolve", app.ResolveIncident)
			mut.POST("/authelia/alerts/:id/resolve", app.AutheliaResolveAlert)
			mut.POST("/authelia/temp-access", app.AutheliaAddTempAccess)
			mut.POST("/authelia/temp-access/:id/revoke", app.AutheliaRevokeTempAccess)
			mut.POST("/authelia/sync", app.AutheliaSync)
			mut.POST("/authelia-instances", app.CreateAutheliaInstance)
			mut.PUT("/authelia-instances/:id", app.UpdateAutheliaInstance)
			mut.DELETE("/authelia-instances/:id", app.DeleteAutheliaInstance)
			mut.POST("/authelia-instances/:id/test", app.TestAutheliaInstance)
		}
	}

	// Start periodic sync scheduler (if SYNC_INTERVAL > 0)
	syncInterval := getEnvInt("SYNC_INTERVAL", 0)
	if syncInterval > 0 {
		go app.startSyncScheduler(ctx, syncInterval)
	}

	// Start recurrent missing-items notification scheduler (if enabled & configured)
	startupSettings := app.settings()
	if startupSettings.NotifyEnabled && startupSettings.GotifyURL != "" && startupSettings.GotifyToken != "" {
		go app.startNotifyScheduler(ctx)
	}

	// Start docker event watcher + retention purge (if the engine is reachable)
	if app.dockerClient != nil {
		go app.startDockerWatcher(ctx)
		go app.runDockerEventPurge(ctx)
	}

	// Start periodic reconcile scheduler (if enabled)
	if startupSettings.ReconcileEnabled && startupSettings.ReconcileIntervalMinutes > 0 {
		go app.startReconcileScheduler(ctx)
	}

	// Start alert rule evaluation scheduler. The loop idles when the master
	// switch is off, so enabling alerts at runtime needs no restart.
	go app.startAlertScheduler(ctx)

	// Session cleanup goroutine
	go func() {
		for {
			time.Sleep(15 * time.Minute)
			cleanupSessions()
		}
	}()

	fmt.Printf("synapse v%s listening on %s\n", version, addr)

	srv := &http.Server{Addr: addr, Handler: r}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}

func (app *App) HandleCheckSetup(c *gin.Context) {
	count, err := app.database.CountAdminUsersCtx(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"setup": count > 0})
}

func (app *App) HandleLogin(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Setup    bool   `json:"setup"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	count, _ := app.database.CountAdminUsersCtx(c.Request.Context())

	if input.Setup && count > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Setup already completed"})
		return
	}

	if count == 0 {
		if len(input.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
			return
		}
		userID, err := app.database.CreateAdminUser(input.Username, string(hash))
		if err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
			return
		}
		sessionID := generateSessionID()
		sessionStoreMu.Lock()
		sessionStore[sessionID] = sessionInfo{Expiry: time.Now().Add(24 * time.Hour), UserID: userID}
		sessionStoreMu.Unlock()
		setSessionCookie(c, sessionID)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}

	user, err := app.database.GetAdminUserCtx(c.Request.Context(), input.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	sessionID := generateSessionID()
	sessionStoreMu.Lock()
	sessionStore[sessionID] = sessionInfo{Expiry: time.Now().Add(24 * time.Hour), UserID: user.ID}
	sessionStoreMu.Unlock()
	setSessionCookie(c, sessionID)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (app *App) HandleLogout(c *gin.Context) {
	sessionID, err := c.Cookie("session")
	if err == nil && sessionID != "" {
		sessionStoreMu.Lock()
		delete(sessionStore, sessionID)
		sessionStoreMu.Unlock()
	}
	c.SetCookie("session", "", -1, "/", "", false, true)
	for _, n := range []string{"oidc_state", "oidc_nonce", "oidc_verifier"} {
		c.SetCookie(n, "", -1, "/", "", false, true)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// HandleOIDCStatus reports whether OIDC login is configured (no secrets).
func (app *App) HandleOIDCStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"enabled": app.oidcEnabled(), "issuer": app.oidcCfg.Issuer})
}

// HandleOIDCLogin starts Authorization Code + PKCE S256 against Authelia.
func (app *App) HandleOIDCLogin(c *gin.Context) {
	if !app.oidcEnabled() || app.oauth2Cfg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "oidc not configured"})
		return
	}
	state, err := auth.GenerateStateNonce()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}
	nonce, err := auth.GenerateStateNonce()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate nonce"})
		return
	}
	verifier, err := auth.GenerateVerifier()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate verifier"})
		return
	}
	c.SetCookie("oidc_state", state, 300, "/", "", false, true)
	c.SetCookie("oidc_nonce", nonce, 300, "/", "", false, true)
	c.SetCookie("oidc_verifier", verifier, 300, "/", "", false, true)
	url := app.oauth2Cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", auth.ChallengeS256(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	c.Redirect(http.StatusFound, url)
}

// HandleOIDCCallback validates state/nonce, exchanges the code, verifies the
// ID token, enforces email_verified, links/provisions the user by email, and
// creates an OIDC session.
func (app *App) HandleOIDCCallback(c *gin.Context) {
	if !app.oidcEnabled() || app.oauth2Cfg == nil || app.oidcVerifier == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "oidc not configured"})
		return
	}
	state, err := c.Cookie("oidc_state")
	if err != nil || state == "" || c.Query("state") != state {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid state"})
		return
	}
	nonce, err := c.Cookie("oidc_nonce")
	if err != nil || nonce == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid nonce"})
		return
	}
	verifier, err := c.Cookie("oidc_verifier")
	if err != nil || verifier == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid verifier"})
		return
	}
	if ec := c.Query("error"); ec != "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "oidc: " + ec})
		return
	}
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}
	ctx := c.Request.Context()
	token, err := app.oauth2Cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "code exchange failed"})
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing id_token"})
		return
	}
	idToken, err := app.oidcVerifier.Verify(ctx, rawID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid id_token"})
		return
	}
	var nonceClaims struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&nonceClaims); err != nil || nonceClaims.Nonce != nonce {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid nonce"})
		return
	}
	var claims auth.Claims
	if err := idToken.Claims(&claims); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
		return
	}
	if err := claims.Validate(); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	userID, err := auth.LinkOrProvision(app.database, claims.Email, claims.Sub)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision user"})
		return
	}
	sessionID := generateSessionID()
	if sessionID == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}
	sessionStoreMu.Lock()
	sessionStore[sessionID] = sessionInfo{Expiry: time.Now().Add(24 * time.Hour), UserID: userID, OIDC: true, Email: claims.Email, Groups: claims.Groups}
	sessionStoreMu.Unlock()
	setSessionCookie(c, sessionID)
	for _, n := range []string{"oidc_state", "oidc_nonce", "oidc_verifier"} {
		c.SetCookie(n, "", -1, "/", "", false, true)
	}
	c.Redirect(http.StatusFound, "/")
}

// sessionUserID returns the authenticated user id set by authMiddleware.
func sessionUserID(c *gin.Context) (int64, bool) {
	v, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	id, ok := v.(int64)
	return id, ok
}

// CreateToken provisions a new bearer API token owned by the session user.
// The plaintext secret is returned exactly once; only its hash is stored.
func (app *App) CreateToken(c *gin.Context) {
	userID, ok := sessionUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	var input struct {
		Name          string `json:"name"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	var expiresAt *time.Time
	if input.ExpiresInDays > 0 {
		t := time.Now().Add(time.Duration(input.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &t
	}
	secret := generateAPIToken()
	if secret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	id, err := app.database.CreateAPIToken(userID, input.Name, hashToken(secret), expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":         id,
		"name":       input.Name,
		"token":      secret, // one-time display
		"created_at": time.Now(),
		"expires_at": expiresAt,
	})
}

// ListTokens returns metadata for the session user's tokens. Secrets are never
// included; only the hash is stored and it is not exposed.
func (app *App) ListTokens(c *gin.Context) {
	userID, ok := sessionUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	tokens, err := app.database.ListAPITokens(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list tokens"})
		return
	}
	c.JSON(http.StatusOK, tokens)
}

// getOwnedToken loads a token by id and verifies it belongs to the session
// user. Writes the error response and returns nil when access is denied.
func (app *App) getOwnedToken(c *gin.Context) *db.APIToken {
	userID, ok := sessionUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return nil
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token id"})
		return nil
	}
	token, err := app.database.GetAPITokenByID(id)
	if err != nil || token == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
		return nil
	}
	if token.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "token belongs to another user"})
		return nil
	}
	return token
}

// RevokeToken revokes an owned token. Revoked tokens fail bearer validation
// immediately, so no mutation can be performed with them.
func (app *App) RevokeToken(c *gin.Context) {
	token := app.getOwnedToken(c)
	if token == nil {
		return
	}
	if err := app.database.RevokeAPIToken(token.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "id": token.ID})
}

// RotateToken replaces an owned token's secret with a fresh one. The previous
// secret stops working immediately; the new secret is returned once.
func (app *App) RotateToken(c *gin.Context) {
	token := app.getOwnedToken(c)
	if token == nil {
		return
	}
	secret := generateAPIToken()
	if secret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	if err := app.database.RotateAPIToken(token.ID, hashToken(secret)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":    token.ID,
		"token": secret, // one-time display
	})
}

func (app *App) Dashboard(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
	c.HTML(http.StatusOK, "index.html", gin.H{
		"Version": version,
	})
}

func (app *App) GetSettings(c *gin.Context) {
	s := app.settings()
	// Check if NPM/Authelia instances have been migrated
	npmInstances, _ := app.database.GetNPMInstances()
	npmMigrated := len(npmInstances) > 0
	autheliaInstances, _ := app.database.GetAutheliaInstances()
	autheliaMigrated := len(autheliaInstances) > 0
	c.JSON(http.StatusOK, gin.H{
		"compose_path":                 s.ComposePath,
		"npm_host":                     s.NPMHost,
		"npm_user":                     s.NPMUser,
		"npm_pass":                     mask(s.NPMPass),
		"npm_migrated":                 npmMigrated,
		"authelia_config_path":         s.AutheliaConfigPath,
		"authelia_db_path":             s.AutheliaDBPath,
		"authelia_sync_enabled":        s.AutheliaSyncEnabled,
		"authelia_default_policy":      s.AutheliaDefaultPolicy,
		"authelia_sync_overrides":      s.AutheliaSyncOverrides,
		"authelia_migrated":            autheliaMigrated,
		"otel_endpoint":                s.OTelEndpoint,
		"otel_enabled":                 s.OTelEnabled,
		"eink_enabled":                 s.EinkEnabled,
		"trmnl_api_token":              s.TrmnlApiToken,
		"notify_enabled":               s.NotifyEnabled,
		"notify_interval_minutes":      s.NotifyIntervalMinutes,
		"gotify_url":                   s.GotifyURL,
		"gotify_token":                 mask(s.GotifyToken),
		"gotify_priority":              s.GotifyPriority,
		"notify_channels":              maskChannelsDoc(s.NotifyChannels),
		"docker_socket":                s.DockerSocket,
		"docker_events_enabled":        s.DockerEventsEnabled,
		"docker_events_retention_days": s.DockerEventsRetentionDays,
		"reconcile_enabled":            s.ReconcileEnabled,
		"reconcile_interval_minutes":   s.ReconcileIntervalMinutes,
		"reconcile_dry_run_default":    s.ReconcileDryRunDefault,
		"notify_docker_die":            s.NotifyDockerDie,
		"notify_docker_health":         s.NotifyDockerHealth,
		"notify_docker_image":          s.NotifyDockerImage,
		"notify_reconcile":             s.NotifyReconcile,
		"notify_alerts":                s.NotifyAlerts,
		"notify_cooldown_minutes":      s.NotifyCooldownMinutes,
		"notify_persistent":            s.NotifyPersistent,
		"alerts_enabled":               s.AlertsEnabled,
		"alert_eval_interval_seconds":  s.AlertEvalIntervalSeconds,
		"alert_reminder_minutes":       s.AlertReminderMinutes,
		"kuma_default_tags":            s.KumaDefaultTags,
	})
}

func (app *App) SaveSettings(c *gin.Context) {
	// Parse raw JSON to detect which fields were explicitly sent
	var raw map[string]json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Only save fields that were explicitly sent in the request body
	pairs := make(map[string]string)

	// Legacy npm_host/user/pass are deprecated — log warning if sent, ignore.
	if _, ok := raw["npm_host"]; ok {
		logging.LogWarn("app", "Legacy npm_host setting is deprecated, use NPM API instead")
	}
	if _, ok := raw["npm_user"]; ok {
		logging.LogWarn("app", "Legacy npm_user setting is deprecated, use NPM API instead")
	}
	if _, ok := raw["npm_pass"]; ok {
		logging.LogWarn("app", "Legacy npm_pass setting is deprecated, use NPM API instead")
	}
	// Legacy authelia_* settings are deprecated — warn if sent, ignore.
	if _, ok := raw["authelia_config_path"]; ok {
		logging.LogWarn("app", "Legacy authelia_config_path setting is deprecated, use Authelia API instead")
	}
	if _, ok := raw["authelia_db_path"]; ok {
		logging.LogWarn("app", "Legacy authelia_db_path setting is deprecated, use Authelia API instead")
	}
	if _, ok := raw["authelia_sync_enabled"]; ok {
		logging.LogWarn("app", "Legacy authelia_sync_enabled setting is deprecated, use Authelia API instead")
	}
	if _, ok := raw["authelia_default_policy"]; ok {
		logging.LogWarn("app", "Legacy authelia_default_policy setting is deprecated, use Authelia API instead")
	}
	if _, ok := raw["authelia_sync_overrides"]; ok {
		logging.LogWarn("app", "Legacy authelia_sync_overrides setting is deprecated, use Authelia API instead")
	}
	if v, ok := raw["compose_path"]; ok {
		var val string
		json.Unmarshal(v, &val)
		pairs["compose_path"] = val
	}
	if v, ok := raw["otel_endpoint"]; ok {
		var val string
		json.Unmarshal(v, &val)
		pairs["otel_endpoint"] = val
	}
	if v, ok := raw["otel_enabled"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["otel_enabled"] = strconv.FormatBool(val)
	}
	if v, ok := raw["eink_enabled"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["eink_enabled"] = strconv.FormatBool(val)
	}
	if v, ok := raw["trmnl_api_token"]; ok {
		var val string
		json.Unmarshal(v, &val)
		pairs["trmnl_api_token"] = val
	}
	if v, ok := raw["notify_enabled"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["notify_enabled"] = strconv.FormatBool(val)
	}
	if v, ok := raw["notify_interval_minutes"]; ok {
		var val int
		json.Unmarshal(v, &val)
		if val < 1 {
			val = 1
		}
		pairs["notify_interval_minutes"] = strconv.Itoa(val)
	}
	if v, ok := raw["gotify_url"]; ok {
		var val string
		json.Unmarshal(v, &val)
		pairs["gotify_url"] = val
	}
	if v, ok := raw["gotify_token"]; ok {
		var val string
		json.Unmarshal(v, &val)
		// Masked token means "keep current" — skip writing so the stored
		// value is preserved. An explicit empty string clears the token.
		if val != "****" {
			pairs["gotify_token"] = val
		}
	}
	if v, ok := raw["notify_channels"]; ok {
		var val string
		if err := json.Unmarshal(v, &val); err == nil && strings.TrimSpace(val) != "" {
			cfgs, perr := channels.ParseChannels(val)
			if perr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": perr.Error()})
				return
			}
			// Masked per-channel tokens mean "keep current": merge tokens
			// from the stored document back in before persisting.
			if cur, cerr := channels.ParseChannels(app.settings().NotifyChannels); cerr == nil {
				for i := range cfgs {
					if cfgs[i].Token == "****" {
						cfgs[i].Token = ""
						for _, c := range cur {
							if c.Type == cfgs[i].Type && c.URL == cfgs[i].URL {
								cfgs[i].Token = c.Token
								break
							}
						}
					}
				}
			}
			if out, merr := json.Marshal(cfgs); merr == nil {
				val = string(out)
			}
			pairs["notify_channels"] = val
		} else if err == nil {
			pairs["notify_channels"] = ""
		}
	}
	if v, ok := raw["gotify_priority"]; ok {
		var val int
		json.Unmarshal(v, &val)
		if val < 0 {
			val = 0
		}
		if val > 10 {
			val = 10
		}
		pairs["gotify_priority"] = strconv.Itoa(val)
	}

	// Docker event tracking + reconcile settings
	if v, ok := raw["docker_socket"]; ok {
		var val string
		json.Unmarshal(v, &val)
		pairs["docker_socket"] = val
	}
	if v, ok := raw["docker_events_enabled"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["docker_events_enabled"] = strconv.FormatBool(val)
	}
	if v, ok := raw["docker_events_retention_days"]; ok {
		var val int
		json.Unmarshal(v, &val)
		if val < 1 {
			val = 1
		}
		if val > 3650 {
			val = 3650
		}
		pairs["docker_events_retention_days"] = strconv.Itoa(val)
	}
	if v, ok := raw["reconcile_enabled"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["reconcile_enabled"] = strconv.FormatBool(val)
	}
	if v, ok := raw["reconcile_interval_minutes"]; ok {
		var val int
		json.Unmarshal(v, &val)
		if val < 1 {
			val = 1
		}
		pairs["reconcile_interval_minutes"] = strconv.Itoa(val)
	}
	if v, ok := raw["reconcile_dry_run_default"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["reconcile_dry_run_default"] = strconv.FormatBool(val)
	}
	if v, ok := raw["notify_docker_die"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["notify_docker_die"] = strconv.FormatBool(val)
	}
	if v, ok := raw["notify_docker_health"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["notify_docker_health"] = strconv.FormatBool(val)
	}
	if v, ok := raw["notify_docker_image"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["notify_docker_image"] = strconv.FormatBool(val)
	}
	if v, ok := raw["notify_reconcile"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["notify_reconcile"] = strconv.FormatBool(val)
	}
	if v, ok := raw["notify_alerts"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["notify_alerts"] = strconv.FormatBool(val)
	}
	if v, ok := raw["alerts_enabled"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["alerts_enabled"] = strconv.FormatBool(val)
	}
	if v, ok := raw["alert_eval_interval_seconds"]; ok {
		var val int
		json.Unmarshal(v, &val)
		if val < 10 {
			val = 10
		}
		if val > 3600 {
			val = 3600
		}
		pairs["alert_eval_interval_seconds"] = strconv.Itoa(val)
	}
	if v, ok := raw["alert_reminder_minutes"]; ok {
		var val int
		json.Unmarshal(v, &val)
		if val < 0 {
			val = 0
		}
		if val > 1440 {
			val = 1440
		}
		pairs["alert_reminder_minutes"] = strconv.Itoa(val)
	}
	if v, ok := raw["notify_cooldown_minutes"]; ok {
		var val int
		json.Unmarshal(v, &val)
		if val < 1 {
			val = 1
		}
		if val > 1440 {
			val = 1440
		}
		pairs["notify_cooldown_minutes"] = strconv.Itoa(val)
	}
	if v, ok := raw["notify_persistent"]; ok {
		var val bool
		json.Unmarshal(v, &val)
		pairs["notify_persistent"] = strconv.FormatBool(val)
	}
	if v, ok := raw["kuma_default_tags"]; ok {
		var val string
		json.Unmarshal(v, &val)
		pairs["kuma_default_tags"] = val
	}

	if err := app.database.SaveSettingsMap(pairs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "saved"})
}

func (app *App) TestNPM(c *gin.Context) {
	start := time.Now()
	logging.LogDebug("app", "Testing NPM connection")

	s := app.settings()
	var input db.Settings
	if err := c.ShouldBindJSON(&input); err == nil {
		if input.NPMHost != "" {
			s.NPMHost = input.NPMHost
		}
		if input.NPMUser != "" {
			s.NPMUser = input.NPMUser
		}
		if input.NPMPass != "" && input.NPMPass != "****" {
			s.NPMPass = input.NPMPass
		}
	}
	clients, _ := app.kumaRegistry.All()
	npmClients, _ := app.npmRegistry.All()
	proxies, err := synclib.GetNPMProxiesWithStatus(npmClients, clients)
	if err != nil && len(proxies) == 0 {
		logging.LogError("app", "NPM connection test failed",
			slog.String("npm_host", s.NPMHost),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)),
		)
		c.JSON(http.StatusOK, gin.H{"ok": false, "message": err.Error()})
		return
	}
	if err != nil {
		logging.LogError("app", "Partial NPM fetch failure during connection test",
			slog.String("npm_host", s.NPMHost),
			slog.String("error", err.Error()),
		)
	}
	logging.LogInfo("app", "NPM connection test successful",
		slog.String("npm_host", s.NPMHost),
		slog.Duration("duration", time.Since(start)),
	)
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "NPM connection successful"})
}

// ─── Kuma Instance Handlers ──────────────────────────────────────────────────

// kumaInstanceJSON is the JSON representation of a Kuma instance, with the
// password masked in responses.
type kumaInstanceJSON struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
}

func toKumaInstanceJSON(k *db.KumaInstance) kumaInstanceJSON {
	return kumaInstanceJSON{
		ID:        k.ID,
		Name:      k.Name,
		URL:       k.URL,
		Username:  k.Username,
		Password:  mask(k.Password),
		Enabled:   k.Enabled,
		CreatedAt: k.CreatedAt.Format(time.RFC3339),
	}
}

type npmInstanceJSON struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
}

func toNPMInstanceJSON(n *db.NPMInstance) npmInstanceJSON {
	return npmInstanceJSON{
		ID:        n.ID,
		Name:      n.Name,
		URL:       n.URL,
		Username:  n.Username,
		Password:  mask(n.Password),
		Enabled:   n.Enabled,
		CreatedAt: n.CreatedAt.Format(time.RFC3339),
	}
}

func (app *App) ListKumaInstances(c *gin.Context) {
	instances, err := app.database.GetKumaInstances()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]kumaInstanceJSON, 0, len(instances))
	for i := range instances {
		result = append(result, toKumaInstanceJSON(&instances[i]))
	}
	c.JSON(http.StatusOK, result)
}

func (app *App) CreateKumaInstance(c *gin.Context) {
	var input struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if input.Name == "" || input.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and url are required"})
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	created, err := app.database.CreateKumaInstance(&db.KumaInstance{
		Name:     input.Name,
		URL:      input.URL,
		Username: input.Username,
		Password: input.Password,
		Enabled:  enabled,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, toKumaInstanceJSON(created))
}

func (app *App) UpdateKumaInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var input struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	existing, err := app.database.GetKumaInstance(id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
		return
	}
	enabled := existing.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if err := app.database.UpdateKumaInstance(id, &db.KumaInstance{
		Name:     input.Name,
		URL:      input.URL,
		Username: input.Username,
		Password: input.Password, // empty = keep existing
		Enabled:  enabled,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	app.kumaRegistry.Invalidate(int(id))
	updated, _ := app.database.GetKumaInstance(id)
	c.JSON(http.StatusOK, toKumaInstanceJSON(updated))
}

func (app *App) DeleteKumaInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	app.kumaRegistry.Invalidate(int(id))
	if err := app.database.DeleteKumaInstance(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (app *App) TestKumaInstance(c *gin.Context) {
	start := time.Now()
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	inst, err := app.database.GetKumaInstance(id)
	if err != nil || inst == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
		return
	}
	logging.LogDebug("app", "Testing Kuma instance connection",
		slog.String("instance", inst.Name),
		slog.String("kuma_url", inst.URL),
	)
	monitors, err := kuma.QueryMonitorsViaSocketIO(inst.URL, inst.Username, inst.Password)
	if err != nil {
		logging.LogError("app", "Kuma instance connection test failed",
			slog.String("instance", inst.Name),
			slog.String("kuma_url", inst.URL),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)),
		)
		c.JSON(http.StatusOK, gin.H{"ok": false, "message": err.Error()})
		return
	}
	logging.LogInfo("app", "Kuma instance connection test successful",
		slog.String("instance", inst.Name),
		slog.String("kuma_url", inst.URL),
		slog.Int("monitor_count", len(monitors)),
		slog.Duration("duration", time.Since(start)),
	)
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": fmt.Sprintf("Connected, %d monitors found", len(monitors))})
}

// --- NPM instance handlers ---

func (app *App) ListNPMInstances(c *gin.Context) {
	instances, err := app.database.GetNPMInstances()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]npmInstanceJSON, 0, len(instances))
	for i := range instances {
		result = append(result, toNPMInstanceJSON(&instances[i]))
	}
	c.JSON(http.StatusOK, result)
}

func (app *App) CreateNPMInstance(c *gin.Context) {
	var input struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if input.Name == "" || input.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and url are required"})
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	created, err := app.database.CreateNPMInstance(&db.NPMInstance{
		Name:     input.Name,
		URL:      input.URL,
		Username: input.Username,
		Password: input.Password,
		Enabled:  enabled,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, toNPMInstanceJSON(created))
}

func (app *App) UpdateNPMInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var input struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	existing, err := app.database.GetNPMInstance(id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
		return
	}
	enabled := existing.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if err := app.database.UpdateNPMInstance(id, &db.NPMInstance{
		Name:     input.Name,
		URL:      input.URL,
		Username: input.Username,
		Password: input.Password,
		Enabled:  enabled,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	app.npmRegistry.Invalidate(int(id))
	updated, _ := app.database.GetNPMInstance(id)
	c.JSON(http.StatusOK, toNPMInstanceJSON(updated))
}

func (app *App) DeleteNPMInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	app.npmRegistry.Invalidate(int(id))
	if err := app.database.DeleteNPMInstance(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (app *App) TestNPMInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	inst, err := app.database.GetNPMInstance(id)
	if err != nil || inst == nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "instance not found"})
		return
	}
	client := npm.NewClient(inst.URL, inst.Username, inst.Password)
	proxies, err := client.GetProxyHosts()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": fmt.Sprintf("Connected, %d proxy hosts found", len(proxies))})
}

// --- Authelia instance handlers ---

type autheliaInstanceJSON struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	ConfigPath     string `json:"config_path"`
	DBPath         string `json:"db_path"`
	DefaultPolicy  string `json:"default_policy"`
	Overrides      string `json:"overrides"`
	AutoSync       bool   `json:"auto_sync"`
	Enabled        bool   `json:"enabled"`
	NPMInstanceIDs string `json:"npm_instance_ids"`
	CreatedAt      string `json:"created_at"`
}

func toAutheliaInstanceJSON(a *db.AutheliaInstance) autheliaInstanceJSON {
	return autheliaInstanceJSON{
		ID:             a.ID,
		Name:           a.Name,
		ConfigPath:     a.ConfigPath,
		DBPath:         a.DBPath,
		DefaultPolicy:  a.DefaultPolicy,
		Overrides:      a.Overrides,
		AutoSync:       a.AutoSync,
		Enabled:        a.Enabled,
		NPMInstanceIDs: a.NPMInstanceIDs,
		CreatedAt:      a.CreatedAt.Format(time.RFC3339),
	}
}

func (app *App) ListAutheliaInstances(c *gin.Context) {
	instances, err := app.database.GetAutheliaInstances()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]autheliaInstanceJSON, 0, len(instances))
	for i := range instances {
		result = append(result, toAutheliaInstanceJSON(&instances[i]))
	}
	c.JSON(http.StatusOK, result)
}

func (app *App) CreateAutheliaInstance(c *gin.Context) {
	var input struct {
		Name           string `json:"name"`
		ConfigPath     string `json:"config_path"`
		DBPath         string `json:"db_path"`
		DefaultPolicy  string `json:"default_policy"`
		Overrides      string `json:"overrides"`
		AutoSync       bool   `json:"auto_sync"`
		Enabled        *bool  `json:"enabled"`
		NPMInstanceIDs string `json:"npm_instance_ids"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if input.Name == "" || input.ConfigPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and config_path are required"})
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if input.DefaultPolicy == "" {
		input.DefaultPolicy = "one_factor"
	}
	if input.Overrides == "" {
		input.Overrides = "{}"
	}
	if input.NPMInstanceIDs == "" {
		input.NPMInstanceIDs = "[]"
	}
	created, err := app.database.CreateAutheliaInstance(&db.AutheliaInstance{
		Name:           input.Name,
		ConfigPath:     input.ConfigPath,
		DBPath:         input.DBPath,
		DefaultPolicy:  input.DefaultPolicy,
		Overrides:      input.Overrides,
		AutoSync:       input.AutoSync,
		Enabled:        enabled,
		NPMInstanceIDs: input.NPMInstanceIDs,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, toAutheliaInstanceJSON(created))
}

func (app *App) UpdateAutheliaInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var input struct {
		Name           string `json:"name"`
		ConfigPath     string `json:"config_path"`
		DBPath         string `json:"db_path"`
		DefaultPolicy  string `json:"default_policy"`
		Overrides      string `json:"overrides"`
		AutoSync       *bool  `json:"auto_sync"`
		Enabled        *bool  `json:"enabled"`
		NPMInstanceIDs string `json:"npm_instance_ids"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	existing, err := app.database.GetAutheliaInstance(id)
	if err != nil || existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
		return
	}
	// Preserve existing fields if not sent
	name := input.Name
	if name == "" {
		name = existing.Name
	}
	configPath := input.ConfigPath
	if configPath == "" {
		configPath = existing.ConfigPath
	}
	dbPath := input.DBPath
	if dbPath == "" {
		dbPath = existing.DBPath
	}
	defaultPolicy := input.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = existing.DefaultPolicy
	}
	overrides := input.Overrides
	if overrides == "" {
		overrides = existing.Overrides
	}
	npmInstanceIDs := input.NPMInstanceIDs
	if npmInstanceIDs == "" {
		npmInstanceIDs = existing.NPMInstanceIDs
	}
	autoSync := existing.AutoSync
	if input.AutoSync != nil {
		autoSync = *input.AutoSync
	}
	enabled := existing.Enabled
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if err := app.database.UpdateAutheliaInstance(id, &db.AutheliaInstance{
		Name:           name,
		ConfigPath:     configPath,
		DBPath:         dbPath,
		DefaultPolicy:  defaultPolicy,
		Overrides:      overrides,
		AutoSync:       autoSync,
		Enabled:        enabled,
		NPMInstanceIDs: npmInstanceIDs,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	updated, _ := app.database.GetAutheliaInstance(id)
	c.JSON(http.StatusOK, toAutheliaInstanceJSON(updated))
}

func (app *App) DeleteAutheliaInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := app.database.DeleteAutheliaInstance(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (app *App) TestAutheliaInstance(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	inst, err := app.database.GetAutheliaInstance(id)
	if err != nil || inst == nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "instance not found"})
		return
	}
	// Test config file readability
	if _, err := os.ReadFile(inst.ConfigPath); err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "message": "config file not readable: " + err.Error()})
		return
	}
	// Test config file parse
	ac, err := authelia.ParseConfig(inst.ConfigPath)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "message": "config parse error: " + err.Error()})
		return
	}
	// Test DB path accessibility
	if inst.DBPath != "" {
		if _, err := os.Stat(inst.DBPath); err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "message": "db path not accessible: " + err.Error()})
			return
		}
	}
	domains := authelia.GetDomains(ac)
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": fmt.Sprintf("Config readable, %d domains found", len(domains))})
}

func (app *App) Status(c *gin.Context) {
	s := app.settings()

	// Docker health
	var dockerErr string
	services, err := synclib.LoadServices(s.ComposePath)
	dockerCount := 0
	if err == nil {
		dockerCount = len(services)
	} else {
		dockerErr = err.Error()
	}

	// Kuma clients (used for NPM status + kuma health)
	clients, _ := app.kumaRegistry.All()
	npmClients, _ := app.npmRegistry.All()

	kumaInstances, _ := app.database.GetEnabledKumaInstances()
	npmInstances, _ := app.database.GetEnabledNPMInstances()

	// The four upstream-dependent sections below run concurrently. Each used
	// to run sequentially, so the response time was the SUM of every NPM and
	// Kuma instance round trip (up to 30s per unreachable instance); with
	// parallelism it is the MAX. The npm/kuma clients cache results for 15s,
	// so the burst of dashboard requests shares a single upstream fetch.
	var (
		wg             sync.WaitGroup
		mu             sync.Mutex
		npmCount       int
		npmErr         string
		kumaErr        string
		monitorCount   int
		npmHealthList  []gin.H
		kumaHealthList []gin.H
	)

	// NPM proxy hosts + Kuma "in kuma" status. Partial results are still
	// served when only some instances fail.
	wg.Add(1)
	go func() {
		defer wg.Done()
		npmProxies, npmFetchErr := synclib.GetNPMProxiesWithStatus(npmClients, clients)
		mu.Lock()
		npmCount = len(npmProxies)
		if npmFetchErr != nil {
			npmErr = npmFetchErr.Error()
		}
		mu.Unlock()
	}()

	// Kuma health — check each enabled instance. Health is ok only if ALL
	// enabled instances are reachable.
	wg.Add(1)
	go func() {
		defer wg.Done()
		list := make([]gin.H, 0, len(kumaInstances))
		errStr := ""
		for _, inst := range kumaInstances {
			instErr := ""
			if _, err := app.kumaRegistry.Get(int(inst.ID)); err != nil {
				instErr = err.Error()
			}
			list = append(list, gin.H{
				"id":         inst.ID,
				"name":       inst.Name,
				"ok":         instErr == "",
				"last_error": instErr,
			})
			if instErr != "" {
				if errStr == "" {
					errStr = instErr
				} else {
					errStr = inst.Name + ": " + instErr
				}
			}
		}
		if len(kumaInstances) == 0 {
			errStr = "no Kuma instances configured"
		}
		mu.Lock()
		kumaHealthList = list
		kumaErr = errStr
		mu.Unlock()
	}()

	// Live monitor total across all connected Kuma instances.
	wg.Add(1)
	go func() {
		defer wg.Done()
		total, _ := app.kumaMonitorCount(clients)
		mu.Lock()
		monitorCount = total
		mu.Unlock()
	}()

	// NPM per-instance health. Uses the registry's cached clients (JWT +
	// 15s result cache) instead of a fresh client per request.
	wg.Add(1)
	go func() {
		defer wg.Done()
		list := make([]gin.H, 0, len(npmInstances))
		for _, inst := range npmInstances {
			errMsg := ""
			cl, err := app.npmRegistry.Get(int(inst.ID))
			if err != nil {
				errMsg = err.Error()
			} else if _, err := cl.GetProxyHosts(); err != nil {
				errMsg = err.Error()
			}
			list = append(list, gin.H{
				"id":         inst.ID,
				"name":       inst.Name,
				"ok":         errMsg == "",
				"last_error": errMsg,
			})
		}
		mu.Lock()
		npmHealthList = list
		mu.Unlock()
	}()

	wg.Wait()

	lastDocker, _ := app.database.GetLatestSyncRun("docker")
	lastNPM, _ := app.database.GetLatestSyncRun("npm")

	connectionHealth := gin.H{
		"docker": gin.H{
			"ok":         dockerErr == "",
			"last_error": dockerErr,
		},
		"npm": gin.H{
			"ok":         npmErr == "",
			"last_error": npmErr,
			"instances":  npmHealthList,
		},
		"kuma": gin.H{
			"ok":         kumaErr == "",
			"last_error": kumaErr,
			"instances":  kumaHealthList,
		},
	}

	openIncidents := 0
	if n, err := app.database.CountOpenIncidents(); err == nil {
		openIncidents = n
	}

	c.JSON(http.StatusOK, gin.H{
		"docker_count":      dockerCount,
		"npm_count":         npmCount,
		"npm_error":         npmErr,
		"kuma_error":        kumaErr,
		"docker_error":      dockerErr,
		"monitor_count":     monitorCount,
		"last_docker":       lastDocker,
		"last_npm":          lastNPM,
		"running":           app.running,
		"open_incidents":    openIncidents,
		"connection_health": connectionHealth,
	})
}

// TrmnlStats returns a flat, TRMNL-template-friendly stats payload for
// kumaMonitorCount returns the live monitor total (and how many are up)
// across all connected Kuma instances — matching what the Kuma tab shows.
// The local monitors table only holds monitors Synapse itself synced, so
// using it here would show 0 even when Kuma has dozens of monitors.
// When no instance can be reached it falls back to the sync table count
// so the dashboard never shows a bogus 0.
func (app *App) kumaMonitorCount(clients []kuma.InstanceClient) (total, up int) {
	live := false
	for _, ic := range clients {
		monitors, err := ic.Client.QueryMonitorsViaSocketIO()
		if err != nil {
			continue
		}
		live = true
		total += len(monitors)
		for _, m := range monitors {
			if m.Status == 1 {
				up++
			}
		}
	}
	if !live {
		if n, err := app.database.GetMonitorCount(); err == nil {
			total = n
			up = n // degrade: per-monitor status unknown, report all up
		}
	}
	return total, up
}

// e-ink wall displays. It reuses the Status computation path but flattens
// the response so Liquid templates can read IDX_0.<field> directly.
func (app *App) TrmnlStats(c *gin.Context) {
	s := app.settings()

	// Docker health
	var dockerErr string
	services, err := synclib.LoadServices(s.ComposePath)
	dockerCount := 0
	if err == nil {
		dockerCount = len(services)
	} else {
		dockerErr = err.Error()
	}

	// NPM health
	clients, _ := app.kumaRegistry.All()
	npmClients, _ := app.npmRegistry.All()
	npmCount := 0
	npmErr := ""
	npmProxies, npmFetchErr := synclib.GetNPMProxiesWithStatus(npmClients, clients)
	// Partial results are still served when only some instances fail.
	npmCount = len(npmProxies)
	if npmFetchErr != nil {
		npmErr = npmFetchErr.Error()
	}

	// Kuma health — ok only if ALL enabled instances are reachable.
	kumaErr := ""
	kumaInstances, _ := app.database.GetEnabledKumaInstances()
	if len(kumaInstances) == 0 {
		kumaErr = "no Kuma instances configured"
	} else {
		for _, inst := range kumaInstances {
			if _, err := app.kumaRegistry.Get(int(inst.ID)); err != nil {
				if kumaErr == "" {
					kumaErr = err.Error()
				} else {
					kumaErr = inst.Name + ": " + err.Error()
				}
			}
		}
	}

	monitorCount, up := app.kumaMonitorCount(clients)

	lastDocker, _ := app.database.GetLatestSyncRun("docker")
	lastNPM, _ := app.database.GetLatestSyncRun("npm")

	// Up/down degrade gracefully to counts when detail stats are unavailable.
	down := monitorCount - up

	c.JSON(http.StatusOK, gin.H{
		"docker_count":  dockerCount,
		"npm_count":     npmCount,
		"monitor_count": monitorCount,
		"running":       app.running,
		"last_docker":   lastDocker,
		"last_npm":      lastNPM,
		"docker_ok":     dockerErr == "",
		"npm_ok":        npmErr == "",
		"kuma_ok":       kumaErr == "",
		"up":            up,
		"down":          down,
	})
}

func (app *App) Services(c *gin.Context) {
	s := app.settings()
	clients, _ := app.kumaRegistry.All()
	result, err := synclib.GetDockerServicesWithStatus(s.ComposePath, clients)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if result == nil {
		result = []synclib.ServiceInfo{}
	}
	app.enrichWithContainerState(c.Request.Context(), result)
	c.JSON(http.StatusOK, result)
}

// enrichWithContainerState fills ContainerState/ContainerStatus on each
// ServiceInfo from the Docker Engine (matched by compose container name).
func (app *App) enrichWithContainerState(ctx context.Context, services []synclib.ServiceInfo) {
	if app.dockerClient == nil {
		return
	}
	containers, err := app.dockerClient.ListContainers(ctx)
	if err != nil {
		logging.LogWarn("app", "Docker container list failed during services enrichment",
			slog.String("error", err.Error()),
		)
		return
	}
	stateByContainer := make(map[string]docker.ContainerSummary, len(containers))
	for _, ct := range containers {
		name := ""
		if len(ct.Names) > 0 {
			name = strings.TrimPrefix(ct.Names[0], "/")
		}
		if name != "" {
			stateByContainer[name] = ct
		}
	}
	for i := range services {
		if ct, ok := stateByContainer[services[i].ContainerName]; ok {
			services[i].ContainerState = ct.State
			services[i].ContainerStatus = ct.Status
		}
	}
}

func (app *App) Proxies(c *gin.Context) {
	clients, _ := app.kumaRegistry.All()
	npmClients, _ := app.npmRegistry.All()
	result, err := synclib.GetNPMProxiesWithStatus(npmClients, clients)
	if err != nil && len(result) == 0 {
		// All instances failed — no partial results to serve.
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		// Partial failure: serve the results we have, log the aggregate error.
		logging.LogError("app", "Partial NPM proxy fetch failure",
			slog.String("error", err.Error()),
		)
	}
	if result == nil {
		result = []synclib.ProxyInfo{}
	}
	c.JSON(http.StatusOK, result)
}

type KumaMonitorSummary struct {
	ID              int              `json:"id"`
	Name            string           `json:"name"`
	Type            string           `json:"type"`
	URL             string           `json:"url,omitempty"`
	DockerContainer string           `json:"docker_container,omitempty"`
	Status          int              `json:"status,omitempty"`
	Uptime24h       float64          `json:"uptime_24h,omitempty"`
	Uptime7d        float64          `json:"uptime_7d,omitempty"`
	Uptime1y        float64          `json:"uptime_1y,omitempty"`
	AvgPing         float64          `json:"ping,omitempty"`
	LastMsg         string           `json:"last_msg,omitempty"`
	Interval        int              `json:"interval,omitempty"`
	RetryInterval   int              `json:"retry_interval,omitempty"`
	MaxRetries      int              `json:"maxretries,omitempty"`
	Active          bool             `json:"active"`
	Tags            []kuma.MonitorTag `json:"tags,omitempty"`
	InstanceID      int              `json:"instance_id"`
	InstanceName    string           `json:"instance_name"`
}

func (app *App) KumaMonitors(c *gin.Context) {
	clients, err := app.kumaRegistry.All()
	if err != nil {
		logging.LogWarn("app", "KumaRegistry returned partial results",
			slog.String("error", err.Error()),
		)
	}

	// Build instance name map from DB (lightweight — ent caches internally).
	instances, _ := app.database.GetKumaInstances()
	nameMap := make(map[int]string)
	for _, inst := range instances {
		nameMap[int(inst.ID)] = inst.Name
	}

	result := make([]KumaMonitorSummary, 0, len(clients)*10)
	for _, ic := range clients {
		// GetMonitors() is deprecated and always returns ErrRESTNotSupported
		// (Uptime Kuma has no REST list endpoint); the Socket.IO query is the
		// real path and also carries status/uptime/ping. Cached per client.
		monitors, err := ic.Client.QueryMonitorsViaSocketIO()
		if err != nil {
			logging.LogWarn("app", "Failed to fetch monitors from Kuma instance",
				slog.Int("instance_id", ic.InstanceID),
				slog.String("error", err.Error()),
			)
			continue
		}
		instanceName, _ := nameMap[ic.InstanceID]
		for _, m := range monitors {
			result = append(result, KumaMonitorSummary{
				ID:              m.ID,
				Name:            m.Name,
				Type:            m.Type,
				URL:             m.URL,
				DockerContainer: m.DockerContainer,
				Status:          m.Status,
				Uptime24h:       m.Uptime24h,
				Uptime7d:        m.Uptime7d,
				Uptime1y:        m.Uptime1y,
				AvgPing:         m.Ping,
				LastMsg:         m.LastMsg,
				Interval:        m.Interval,
				RetryInterval:   m.RetryInterval,
				MaxRetries:      m.MaxRetries,
				Active:          m.Active,
				Tags:            m.Tags,
				InstanceID:      ic.InstanceID,
				InstanceName:    instanceName,
			})
		}
	}

	if result == nil {
		result = []KumaMonitorSummary{}
	}

	c.JSON(http.StatusOK, result)
}

func (app *App) KumaMonitorStats(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor id"})
		return
	}
	instanceID, err := strconv.Atoi(c.Query("instance"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing instance query param"})
		return
	}

	client, err := app.kumaRegistry.Get(instanceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("instance %d not found or unreachable", instanceID)})
		return
	}

	stats, err := kuma.GetMonitorStats(client, id)
	if err != nil {
		logging.LogWarn("app", "Socket.IO monitor stats failed",
			slog.Int("monitor_id", id),
			slog.Int("instance_id", instanceID),
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func (app *App) PauseKumaMonitor(c *gin.Context) {
	kumaID, err := strconv.Atoi(c.Param("kumaId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor id"})
		return
	}
	instanceID, err := strconv.Atoi(c.Query("instance"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing instance query param"})
		return
	}
	client, err := app.kumaRegistry.Get(instanceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("instance %d not found or unreachable", instanceID)})
		return
	}
	if err := client.PauseMonitorViaSocketIO(kumaID); err != nil {
		logging.LogWarn("app", "Socket.IO pause monitor failed", slog.Int("monitor_id", kumaID), slog.Int("instance_id", instanceID), slog.String("error", err.Error()))
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (app *App) ResumeKumaMonitor(c *gin.Context) {
	kumaID, err := strconv.Atoi(c.Param("kumaId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor id"})
		return
	}
	instanceID, err := strconv.Atoi(c.Query("instance"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing instance query param"})
		return
	}
	client, err := app.kumaRegistry.Get(instanceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("instance %d not found or unreachable", instanceID)})
		return
	}
	if err := client.ResumeMonitorViaSocketIO(kumaID); err != nil {
		logging.LogWarn("app", "Socket.IO resume monitor failed", slog.Int("monitor_id", kumaID), slog.Int("instance_id", instanceID), slog.String("error", err.Error()))
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (app *App) SetMonitorTags(c *gin.Context) {
	kumaID, err := strconv.Atoi(c.Param("kumaId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor id"})
		return
	}
	instanceID, err := strconv.Atoi(c.Query("instance"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or missing instance query param"})
		return
	}
	client, err := app.kumaRegistry.Get(instanceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("instance %d not found or unreachable", instanceID)})
		return
	}
	// Parse desired tags: support {tags:[...]} or raw array.
	var rawBody json.RawMessage
	if err := c.ShouldBindJSON(&rawBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	desiredIDs := []int{}
	// Try wrapper object {tags: [...]}
	var wrapper struct {
		Tags json.RawMessage `json:"tags"`
	}
	if err := json.Unmarshal(rawBody, &wrapper); err == nil && len(wrapper.Tags) != 0 {
		rawBody = wrapper.Tags
	}
	// Try []int
	var asInts []int
	if err := json.Unmarshal(rawBody, &asInts); err == nil {
		desiredIDs = asInts
	} else {
		// Try []MonitorTag / []{id,name}
		var asTags []kuma.MonitorTag
		if err := json.Unmarshal(rawBody, &asTags); err == nil {
			for _, t := range asTags {
				if t.ID != 0 {
					desiredIDs = append(desiredIDs, t.ID)
				}
			}
		} else {
			// Try []string (names) — ignore, no ID mapping
			c.JSON(http.StatusBadRequest, gin.H{"error": "tags must be array of ids or tag objects with id"})
			return
		}
	}
	monitors, err := client.QueryMonitorsViaSocketIO()
	if err != nil {
		logging.LogWarn("app", "Failed to fetch monitors for tag diff", slog.Int("instance_id", instanceID), slog.String("error", err.Error()))
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	var cur *kuma.KumaMonitor
	for i := range monitors {
		if monitors[i].ID == kumaID {
			cur = &monitors[i]
			break
		}
	}
	if cur == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("monitor %d not found", kumaID)})
		return
	}
	currentSet := make(map[int]bool)
	for _, t := range cur.Tags {
		currentSet[t.ID] = true
	}
	desiredSet := make(map[int]bool)
	for _, id := range desiredIDs {
		desiredSet[id] = true
	}
	var toAdd, toRemove []int
	for id := range desiredSet {
		if !currentSet[id] {
			toAdd = append(toAdd, id)
		}
	}
	for id := range currentSet {
		if !desiredSet[id] {
			toRemove = append(toRemove, id)
		}
	}
	type tagResult struct {
		Added   []int    `json:"added"`
		Removed []int    `json:"removed"`
		Errors  []string `json:"errors,omitempty"`
	}
	res := tagResult{Added: []int{}, Removed: []int{}}
	var errs []string
	for _, id := range toAdd {
		if err := client.AddMonitorTagViaSocketIO(kumaID, id); err != nil {
			msg := err.Error()
			errs = append(errs, fmt.Sprintf("add %d: %s", id, msg))
			logging.LogWarn("app", "Add monitor tag failed", slog.Int("monitor_id", kumaID), slog.Int("tag_id", id), slog.String("error", msg))
		} else {
			res.Added = append(res.Added, id)
		}
	}
	for _, id := range toRemove {
		if err := client.DeleteMonitorTagViaSocketIO(kumaID, id); err != nil {
			msg := err.Error()
			errs = append(errs, fmt.Sprintf("delete %d: %s", id, msg))
			logging.LogWarn("app", "Delete monitor tag failed", slog.Int("monitor_id", kumaID), slog.Int("tag_id", id), slog.String("error", msg))
		} else {
			res.Removed = append(res.Removed, id)
		}
	}
	res.Errors = errs
	c.JSON(http.StatusOK, res)
}

func (app *App) SyncHistory(c *gin.Context) {
	source := c.Query("source")
	runs, err := app.database.GetSyncRuns(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if runs == nil {
		runs = []db.SyncRun{}
	}

	if source != "" {
		filtered := []db.SyncRun{}
		for _, r := range runs {
			if r.Source == source {
				filtered = append(filtered, r)
			}
		}
		runs = filtered
	}

	c.JSON(http.StatusOK, runs)
}

// Reconcile runs the reconciliation engine over service links. With
// dry_run=true (the default, from settings) it reports intended changes
// without applying them.
func (app *App) Reconcile(c *gin.Context) {
	var input struct {
		DryRun  *bool  `json:"dry_run"`
		Service string `json:"service"`
	}
	if err := c.ShouldBindJSON(&input); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s := app.settings()
	dryRun := s.ReconcileDryRunDefault
	if input.DryRun != nil {
		dryRun = *input.DryRun
	}

	npmClients, _ := app.npmRegistry.All()
	kumaClients, _ := app.kumaRegistry.All()
	result := synclib.RunReconcile(
		s.ComposePath, npmClients, kumaClients, app.database,
		synclib.ReconcileOptions{DryRun: dryRun, OnlyService: input.Service},
		nil,
	)

	c.JSON(http.StatusOK, result)
}

// ReconcileRuns lists persisted reconcile runs (newest first).
func (app *App) ReconcileRuns(c *gin.Context) {
	runs, err := app.database.GetSyncRuns(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	filtered := []db.SyncRun{}
	for _, r := range runs {
		if r.Source == "reconcile" {
			filtered = append(filtered, r)
		}
	}
	c.JSON(http.StatusOK, filtered)
}

// DockerEvents lists persisted docker events with optional filters.
func (app *App) DockerEvents(c *gin.Context) {
	f := db.DockerEventFilter{
		EventType: c.Query("type"),
		Action:    c.Query("action"),
		Container: c.Query("container"),
	}
	if since := c.Query("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid since: expected RFC3339 timestamp"})
			return
		}
		f.Since = &t
	}
	if limit := c.Query("limit"); limit != "" {
		n, err := strconv.Atoi(limit)
		if err != nil || n < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		if n > 500 {
			n = 500
		}
		f.Limit = n
	}
	events, err := app.database.ListDockerEvents(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if events == nil {
		events = []db.DockerEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// FeedItem is a single entry in the unified events feed.
type FeedItem struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"` // "docker" | "reconcile"
	Title  string    `json:"title"`
	Detail string    `json:"detail,omitempty"`
	Status string    `json:"status,omitempty"`
}

// EventsFeed returns a unified, time-descending feed of docker events and
// reconcile runs.
func (app *App) EventsFeed(c *gin.Context) {
	events, err := app.database.ListDockerEvents(db.DockerEventFilter{Limit: 50})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	runs, err := app.database.GetSyncRuns(50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]FeedItem, 0, len(events)+len(runs))
	for _, e := range events {
		title := e.Action
		if e.ActorName != "" {
			title = e.ActorName + " " + e.Action
		}
		detail := e.Image
		if e.Image == "" {
			detail = e.EventType
		}
		items = append(items, FeedItem{
			Time:   e.CreatedAt,
			Kind:   "docker",
			Title:  title,
			Detail: detail,
			Status: e.Status,
		})
	}
	for _, r := range runs {
		if r.Source != "reconcile" {
			continue
		}
		items = append(items, FeedItem{
			Time:   r.StartedAt,
			Kind:   "reconcile",
			Title:  "Reconcile " + r.Status,
			Detail: fmt.Sprintf("added %d, updated %d, skipped %d, failed %d", r.Added, r.Updated, r.Skipped, r.Failed),
			Status: r.Status,
		})
	}

	// Merge by time descending, capped at 100 entries.
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Time.After(items[j-1].Time); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
	if len(items) > 100 {
		items = items[:100]
	}
	c.JSON(http.StatusOK, items)
}

func (app *App) DockerSync(c *gin.Context) {
	s := app.settings()

	app.mu.Lock()
	if app.running {
		app.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "sync already running"})
		return
	}
	app.running = true
	app.mu.Unlock()

	go func() {
		defer func() {
			app.mu.Lock()
			app.running = false
			app.progressChans = nil
			app.mu.Unlock()
		}()

		clients, _ := app.kumaRegistry.All()
		synclib.RunDockerSync(s.ComposePath, clients, app.database, func(p synclib.Progress) {
			app.mu.Lock()
			for _, ch := range app.progressChans {
				select {
				case ch <- p:
				default:
				}
			}
			app.mu.Unlock()
		})
	}()

	c.JSON(http.StatusAccepted, gin.H{"status": "started", "source": "docker"})
}

func (app *App) NPMSync(c *gin.Context) {
	app.mu.Lock()
	if app.running {
		app.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "sync already running"})
		return
	}
	app.running = true
	app.mu.Unlock()

	go func() {
		defer func() {
			app.mu.Lock()
			app.running = false
			app.progressChans = nil
			app.mu.Unlock()
		}()

		clients, _ := app.kumaRegistry.All()
		npmClients, _ := app.npmRegistry.All()
		synclib.RunNPMSync(npmClients, clients, app.database, func(p synclib.Progress) {
			app.mu.Lock()
			for _, ch := range app.progressChans {
				select {
				case ch <- p:
				default:
				}
			}
			app.mu.Unlock()
		})
	}()

	c.JSON(http.StatusAccepted, gin.H{"status": "started", "source": "npm"})
}

// startSyncScheduler runs periodic docker and NPM syncs on a configurable interval.
// It is intended to run as a background goroutine and respects context cancellation.
func (app *App) startSyncScheduler(ctx context.Context, intervalMinutes int) {
	logging.LogInfo("app", "Sync scheduler started",
		slog.Int("interval_minutes", intervalMinutes),
	)
	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logging.LogInfo("app", "Sync scheduler stopped")
			return
		case <-ticker.C:
			logging.LogDebug("app", "Scheduler tick",
				slog.Int("interval_minutes", intervalMinutes),
			)
			app.runScheduledSync()
		}
	}
}

// runScheduledSync executes both docker and NPM syncs sequentially with proper locking.
func (app *App) runScheduledSync() {
	app.mu.Lock()
	if app.running {
		app.mu.Unlock()
		logging.LogDebug("app", "Scheduled sync skipped — already running")
		return
	}
	app.running = true
	app.mu.Unlock()

	defer func() {
		app.mu.Lock()
		app.running = false
		app.mu.Unlock()
	}()

	s := app.settings()
	clients, _ := app.kumaRegistry.All()
	logging.LogInfo("app", "Starting scheduled Docker sync",
		slog.String("compose_path", s.ComposePath),
		slog.Int("kuma_instances", len(clients)),
	)

	synclib.RunDockerSync(s.ComposePath, clients, app.database, func(p synclib.Progress) {
		logging.LogDebug("app", "Docker sync progress",
			slog.Int("current", p.Current),
			slog.Int("total", p.Total),
			slog.String("status", p.Status),
			slog.String("message", p.Message),
		)
	})

	log.Println("scheduler: starting periodic npm sync")

	npmClients, _ := app.npmRegistry.All()
	synclib.RunNPMSync(npmClients, clients, app.database, func(p synclib.Progress) {
		log.Printf("[scheduler] npm sync: [%d/%d] %s - %s", p.Current, p.Total, p.Status, p.Message)
	})

	log.Println("scheduler: periodic sync complete")
}

// startNotifyScheduler runs a recurrent checker that reports items missing
// from Uptime Kuma via Gotify. Settings are re-read on every tick so changes
// apply without a restart; when notifications are disabled or unconfigured the
// goroutine idles (re-checking next tick) instead of exiting, so re-enabling
// needs no restart.
func (app *App) startNotifyScheduler(ctx context.Context) {
	logging.LogInfo("app", "Notify scheduler started")
	defer logging.LogInfo("app", "Notify scheduler stopped")

	for {
		s := app.settings()
		interval := s.NotifyIntervalMinutes
		if interval < 1 {
			interval = 1
		}

		timer := time.NewTimer(time.Duration(interval) * time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if !s.NotifyEnabled || s.GotifyURL == "" || s.GotifyToken == "" {
				continue // idle — re-check settings next tick
			}
			app.runNotifyCheck(ctx)
		}
	}
}

// runNotifyCheck computes items missing from Uptime Kuma and sends a Gotify
// notification. Degraded runs (no Kuma monitors enumerated, compose load
// failure, no reachable NPM clients while instances are configured) skip the
// notification to avoid false "everything is missing" alarms.
func (app *App) runNotifyCheck(ctx context.Context) {
	s := app.settings()
	start := time.Now()

	clients, _ := app.kumaRegistry.All()
	npmClients, _ := app.npmRegistry.All()

	degraded := false
	var reasons []string

	// If instances are configured but none produced clients, the Kuma picture
	// is untrustworthy — do not report "everything missing".
	enabledKuma, _ := app.database.GetEnabledKumaInstances()
	if len(enabledKuma) > 0 && len(clients) == 0 {
		degraded = true
		reasons = append(reasons, "no Kuma instances reachable")
	}
	enabledNPM, _ := app.database.GetEnabledNPMInstances()
	if len(enabledNPM) > 0 && len(npmClients) == 0 {
		degraded = true
		reasons = append(reasons, "no NPM instances reachable")
	}

	// Build instance name maps for NPM proxy labels.
	npmNameMap := make(map[int]string)
	for _, inst := range enabledNPM {
		npmNameMap[int(inst.ID)] = inst.Name
	}

	var dockerItems, npmItems []notify.Item
	if !degraded {
		services, sErr := synclib.GetDockerServicesWithStatus(s.ComposePath, clients)
		if sErr != nil {
			degraded = true
			reasons = append(reasons, fmt.Sprintf("compose load failed: %v", sErr))
		}
		proxies, pErr := synclib.GetNPMProxiesWithStatus(npmClients, clients)
		if pErr != nil {
			degraded = true
			reasons = append(reasons, fmt.Sprintf("NPM proxy fetch failed: %v", pErr))
		}
		if sErr == nil && pErr == nil {
			links, lerr := app.database.GetServiceLinks()
			if lerr != nil {
				logging.LogWarn("notify", "Failed to load service links for coverage",
					slog.String("error", lerr.Error()))
			}
			dockerItems, npmItems = buildMissingItems(services, proxies, links, npmNameMap)
		} else if sErr == nil {
			// Services loaded but proxies failed: report docker items without link coverage.
			for _, svc := range services {
				dockerItems = append(dockerItems, notify.Item{Name: svc.ContainerName, InKuma: svc.InKuma})
			}
		}
	}

	report := notify.ComputeMissing(dockerItems, npmItems, degraded, reasons)
	if report.Degraded {
		logging.LogWarn("notify", "Skipping missing-items notification — degraded check",
			slog.Any("reasons", report.Reasons),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}
	if report.Total() == 0 {
		logging.LogInfo("notify", "No items missing from Uptime Kuma",
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	title, body := notify.FormatMessage(report)
	client := notify.NewClient(s.GotifyURL, s.GotifyToken, s.GotifyPriority)
	if err := client.SendMessage(ctx, title, body); err != nil {
		logging.LogError("notify", "Failed to send missing-items notification",
			slog.String("error", err.Error()),
		)
		return
	}
	logging.LogInfo("notify", "Sent missing-items notification",
		slog.Int("missing_count", report.Total()),
		slog.Duration("duration", time.Since(start)),
	)
}

// buildMissingItems converts docker services and NPM proxies into notify.Items
// for the missing-from-Kuma report. An item is marked covered (InKuma=true) when
// it has a service link pointing at a Uptime Kuma monitor, so the report does not
// nag about intentionally-linked items whose Kuma monitor name differs from the
// compose container name (a common case with compose project prefixes, e.g.
// container "myproject-web-1" vs monitor "web"). Only Kuma-linked items count;
// linking to NPM alone is not Kuma coverage.
func buildMissingItems(services []synclib.ServiceInfo, proxies []synclib.ProxyInfo, links []db.ServiceLink, npmNameMap map[int]string) (docker, npm []notify.Item) {
	svcCovered := make(map[string]bool, len(links))
	npmCovered := make(map[string]bool, len(links))
	for _, l := range links {
		if l.KumaMonitorID <= 0 {
			continue
		}
		svcCovered[l.ServiceName] = true
		if l.NPMHostName != "" {
			npmCovered[l.NPMHostName] = true
		}
	}

	docker = make([]notify.Item, 0, len(services))
	for _, svc := range services {
		docker = append(docker, notify.Item{
			Name:   svc.ContainerName,
			InKuma: svc.InKuma || svcCovered[svc.Name],
		})
	}

	npm = make([]notify.Item, 0, len(proxies))
	for _, p := range proxies {
		npm = append(npm, notify.Item{
			Name:     p.CNAME,
			InKuma:   p.InKuma || npmCovered[p.CNAME],
			Instance: npmNameMap[p.SourceInstanceID],
		})
	}
	return docker, npm
}

// channelsFor builds the enabled notification channels from settings. When
// the notify_channels document is set it is the single source of truth;
// otherwise a virtual Gotify channel is derived from the legacy gotify_*
// keys so pre-multi-channel configurations keep working unchanged.
func (app *App) channelsFor(s db.Settings) []notify.Notifier {
	if strings.TrimSpace(s.NotifyChannels) != "" {
		cfgs, err := channels.ParseChannels(s.NotifyChannels)
		if err != nil {
			logging.LogError("notify", "Ignoring invalid notify_channels document",
				slog.String("error", err.Error()),
			)
		} else {
			// Global persistent toggle overlays per-channel setting so the
			// setting stays optional and single-checkbox in the UI.
			if s.NotifyPersistent {
				for i := range cfgs {
					cfgs[i].Persistent = true
				}
			}
			built, buildErrs := channels.BuildAll(cfgs)
			for _, berr := range buildErrs {
				logging.LogError("notify", "Skipping invalid notification channel",
					slog.String("error", berr.Error()),
				)
			}
			return built
		}
	}
	// Legacy fallback: single Gotify channel from flat keys.
	if s.GotifyURL == "" || s.GotifyToken == "" {
		return nil
	}
	return []notify.Notifier{notify.NewClientWithPersistent(s.GotifyURL, s.GotifyToken, s.GotifyPriority, s.NotifyPersistent)}
}

// eventNotifierFor builds an EventNotifier from the current settings. A nil or
// disabled notifier is returned when no channel is configured so callers can
// call Notify unconditionally (it no-ops).
func (app *App) eventNotifierFor(s db.Settings) *notify.EventNotifier {
	chs := app.channelsFor(s)
	if len(chs) == 0 {
		return notify.NewEventNotifier(nil, notify.EventNotifierOptions{Enabled: false})
	}
	return notify.NewEventNotifier(
		chs,
		notify.EventNotifierOptions{
			Enabled:  s.NotifyEnabled,
			Cooldown: time.Duration(s.NotifyCooldownMinutes) * time.Minute,
			Toggles: map[notify.Category]bool{
				notify.CatDockerDie:    s.NotifyDockerDie,
				notify.CatDockerHealth: s.NotifyDockerHealth,
				notify.CatDockerImage:  s.NotifyDockerImage,
				notify.CatReconcile:    s.NotifyReconcile,
				notify.CatAlerts:       s.NotifyAlerts,
			},
		},
	)
}

// startDockerWatcher streams docker events while DockerEventsEnabled is set.
// Settings are re-read on every cycle so enabling event tracking mid-run picks
// it up without a restart. The stop tracker distinguishes graceful stops from
// unexpected container deaths.
func (app *App) startDockerWatcher(ctx context.Context) {
	logging.LogInfo("app", "Docker event watcher started")
	defer logging.LogInfo("app", "Docker event watcher stopped")

	tracker := notify.NewContainerStopTracker(60 * time.Second)

	for {
		s := app.settings()
		if !s.DockerEventsEnabled {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}

		notifier := app.eventNotifierFor(s)
		w := docker.NewWatcher(app.dockerClient, docker.WatcherOptions{
			ReconnectBase: 1 * time.Second,
			ReconnectMax:  30 * time.Second,
			OnEvent: func(ev docker.Event) {
				app.handleDockerEvent(ctx, ev, tracker, notifier)
			},
			OnImageUpdate: func(up docker.ImageUpdate) {
				app.handleImageUpdate(ctx, up, notifier)
			},
		})
		w.Run(ctx) // blocks until the context is cancelled
		return
	}
}

// handleDockerEvent persists a docker event and raises notifications for
// unexpected container deaths and unhealthy health checks.
func (app *App) handleDockerEvent(ctx context.Context, ev docker.Event, tracker *notify.ContainerStopTracker, notifier *notify.EventNotifier) {
	de := &db.DockerEvent{
		EventType: ev.Type,
		Action:    ev.Action,
		ActorID:   ev.Actor.ID,
		ActorName: ev.ContainerName(),
		Image:     ev.ImageName(),
		Status:    ev.Status,
		CreatedAt: time.Now(),
	}
	if err := app.database.CreateDockerEvent(de); err != nil {
		logging.LogWarn("app", "Failed to persist docker event",
			slog.String("action", ev.Action),
			slog.String("error", err.Error()),
		)
	}

	name := ev.ContainerName()
	switch ev.Action {
	case "stop":
		tracker.MarkStop(name, time.Now())
	case "die":
		graceful := tracker.WasGraceful(name, time.Now())
		if graceful {
			return // expected stop/restart — no alarm
		}
		notifier.Notify(ctx, notify.CatDockerDie,
			"Container died unexpectedly",
			fmt.Sprintf("%s (%s)", name, ev.ImageName()),
		)
	case "health_status":
		if ev.Actor.Attributes["status"] == "unhealthy" {
			notifier.Notify(ctx, notify.CatDockerHealth,
				"Container health check failing",
				name,
			)
		}
	}
}

// handleImageUpdate persists an image-change event and raises a notification.
func (app *App) handleImageUpdate(ctx context.Context, up docker.ImageUpdate, notifier *notify.EventNotifier) {
	de := &db.DockerEvent{
		EventType: "image",
		Action:    "update",
		ActorID:   up.ContainerID,
		ActorName: up.ContainerName,
		ImageOld:  up.ImageOld,
		ImageNew:  up.ImageNew,
		CreatedAt: time.Now(),
	}
	if err := app.database.CreateDockerEvent(de); err != nil {
		logging.LogWarn("app", "Failed to persist image update event",
			slog.String("container", up.ContainerName),
			slog.String("error", err.Error()),
		)
	}
	notifier.Notify(ctx, notify.CatDockerImage,
		"Container image updated",
		fmt.Sprintf("%s: %s → %s", up.ContainerName, up.ImageOld, up.ImageNew),
	)
}

// runDockerEventPurge removes docker events older than the retention window
// once a day (and once at startup).
func (app *App) runDockerEventPurge(ctx context.Context) {
	purge := func() {
		s := app.settings()
		days := s.DockerEventsRetentionDays
		if days < 1 {
			days = 30
		}
		before := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		n, err := app.database.PurgeDockerEvents(before)
		if err != nil {
			logging.LogWarn("app", "Docker event purge failed",
				slog.String("error", err.Error()),
			)
			return
		}
		if n > 0 {
			logging.LogInfo("app", "Purged old docker events",
				slog.Int("purged", n),
				slog.Int("retention_days", days),
			)
		}
	}

	purge()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}

// appAlertState adapts App's integrations to the alerts.StateSource interface.
type appAlertState struct {
	app *App
}

// Snapshot gathers one evaluation tick's view of live state: Kuma monitor
// status across all enabled instances (later instances win on name
// conflicts), Docker container states, last completed sync runs, and the
// most recent reconcile outcome.
func (a appAlertState) Snapshot() (*alerts.Snapshot, error) {
	ctx := context.Background()
	snap := &alerts.Snapshot{
		MonitorDown:      map[string]bool{},
		ContainerRunning: map[string]bool{},
		LastSyncSuccess:  map[string]time.Time{},
	}

	instances, err := a.app.database.GetEnabledKumaInstances()
	if err != nil {
		return nil, err
	}
	for _, inst := range instances {
		monitors, qerr := kuma.QueryMonitorsViaSocketIO(inst.URL, inst.Username, inst.Password)
		if qerr != nil {
			logging.LogWarn("alerts", "Skipping unreachable Kuma instance",
				slog.String("instance", inst.Name),
				slog.String("error", qerr.Error()),
			)
			continue
		}
		for _, m := range monitors {
			snap.MonitorDown[m.Name] = m.Status == 0 // 0 = down in Kuma
		}
	}

	if a.app.dockerClient != nil {
		containers, err := a.app.dockerClient.ListContainers(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range containers {
			name := strings.TrimPrefix(c.Names[0], "/")
			snap.ContainerRunning[name] = c.State == "running"
		}
	}

	for _, source := range []string{"docker", "npm"} {
		run, err := a.app.database.GetLastCompletedSyncRun(source)
		if err != nil || run == nil || run.FinishedAt == nil {
			continue
		}
		snap.LastSyncSuccess[source] = *run.FinishedAt
	}

	// ReconcileDrift reports whether the most recent reconcile run reported
	// drift or errors (status error/completed_with_errors, applied changes,
	// or failures); nil = no reconcile run yet.
	if run, err := a.app.database.GetLatestSyncRun("reconcile"); err == nil && run != nil {
		drifted := run.Status == "error" || run.Status == "completed_with_errors" || run.Updated > 0 || run.Failed > 0
		snap.ReconcileDrift = &drifted
	}

	return snap, nil
}

// appAlertNotifier adapts App's EventNotifier to the alerts.Notifier interface
// so cooldowns/toggles/fan-out apply unchanged.
type appAlertNotifier struct {
	app *App
	ctx context.Context
}

// NotifyAlert forwards incident transition messages (event is one of
// "opened", "reminder", "resolved") to the configured notification channels.
func (n appAlertNotifier) NotifyAlert(event, ruleName, subject, message string) {
	title := fmt.Sprintf("Alert %s: %s", event, ruleName)
	if subject != "" {
		message = fmt.Sprintf("%s (%s)", message, subject)
	}
	n.app.eventNotifierFor(n.app.settings()).Notify(n.ctx, notify.CatAlerts, title, message)
}

// startAlertScheduler evaluates alert rules on an interval. Settings are
// re-read every tick so interval/enable changes apply without a restart; when
// alerts are disabled the goroutine idles instead of exiting.
func (app *App) startAlertScheduler(ctx context.Context) {
	logging.LogInfo("alerts", "Alert scheduler started")
	defer logging.LogInfo("alerts", "Alert scheduler stopped")

	for {
		s := app.settings()
		interval := s.AlertEvalIntervalSeconds
		if interval < 10 {
			interval = 10
		}

		timer := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if !s.AlertsEnabled {
				continue // idle — re-check settings next tick
			}
			engine := alerts.NewEngine(app.database, appAlertState{app: app}, appAlertNotifier{app: app, ctx: ctx})
			engine.ReminderInterval = time.Duration(s.AlertReminderMinutes) * time.Minute
			if err := engine.Evaluate(); err != nil {
				logging.LogError("alerts", "Alert evaluation failed",
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

// startReconcileScheduler runs the reconcile engine on an interval. Settings
// are re-read every tick; when reconcile is disabled the goroutine idles.
func (app *App) startReconcileScheduler(ctx context.Context) {
	logging.LogInfo("app", "Reconcile scheduler started")
	defer logging.LogInfo("app", "Reconcile scheduler stopped")

	for {
		s := app.settings()
		if !s.ReconcileEnabled {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
				continue
			}
		}
		interval := s.ReconcileIntervalMinutes
		if interval < 1 {
			interval = 60
		}

		timer := time.NewTimer(time.Duration(interval) * time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			app.runScheduledReconcile(ctx)
		}
	}
}

// runScheduledReconcile executes one reconcile pass and notifies when changes
// were found or the run hit errors.
func (app *App) runScheduledReconcile(ctx context.Context) {
	s := app.settings()
	npmClients, _ := app.npmRegistry.All()
	kumaClients, _ := app.kumaRegistry.All()
	result := synclib.RunReconcile(
		s.ComposePath, npmClients, kumaClients, app.database,
		synclib.ReconcileOptions{DryRun: s.ReconcileDryRunDefault},
		nil,
	)

	if result.Run.Status != "completed_with_errors" && len(result.Changes) == 0 {
		return
	}

	var b strings.Builder
	for _, ch := range result.Changes {
		fmt.Fprintf(&b, "- %s/%s: %s\n", ch.Service, ch.Target, ch.Detail)
	}
	if b.Len() == 0 {
		b.WriteString("(no details)")
	}

	title := fmt.Sprintf("Reconcile finished: %d change(s), %d failed", len(result.Changes), result.Run.Failed)
	app.eventNotifierFor(s).Notify(ctx, notify.CatReconcile, title, strings.TrimSpace(b.String()))
}

// NotifyTest sends a fixed test message to verify notification channel
// configuration. An optional {channel: "<name>"} body targets one channel;
// without it every enabled channel is tested and reported individually.
func (app *App) NotifyTest(c *gin.Context) {
	s := app.settings()

	var body struct {
		Channel string `json:"channel"`
	}
	_ = c.ShouldBindJSON(&body) // empty/absent body = test all

	type result struct {
		Channel string `json:"channel"`
		OK      bool   `json:"ok"`
		Error   string `json:"error,omitempty"`
	}

	build := func() []notify.Notifier {
		if strings.TrimSpace(s.NotifyChannels) != "" {
			cfgs, err := channels.ParseChannels(s.NotifyChannels)
			if err == nil {
				built, _ := channels.BuildAll(cfgs)
				return built
			}
			logging.LogError("notify", "Invalid notify_channels document",
				slog.String("error", err.Error()),
			)
		}
		return app.channelsFor(s)
	}

	all := build()
	if len(all) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "No notification channels configured — add one in Settings"})
		return
	}

	results := make([]result, 0, len(all))
	tested := 0
	for _, ch := range all {
		if !ch.Enabled() {
			continue
		}
		if body.Channel != "" && ch.Name() != body.Channel {
			continue
		}
		tested++
		err := ch.Send(c.Request.Context(), notify.CatReconcile,
			"Synapse test notification", "Synapse test notification — your configuration is working")
		r := result{Channel: ch.Name(), OK: err == nil}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
	}

	if tested == 0 {
		msg := "No enabled notification channels matched"
		if body.Channel != "" {
			msg = fmt.Sprintf("Channel %q not found or disabled", body.Channel)
		}
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": msg})
		return
	}

	ok := true
	for _, r := range results {
		if !r.OK {
			ok = false
		}
	}
	status := http.StatusOK
	if !ok {
		status = http.StatusInternalServerError
	}
	c.JSON(status, gin.H{"ok": ok, "results": results})
}

// NotifyMissing returns the current items missing from Uptime Kuma.
func (app *App) NotifyMissing(c *gin.Context) {
	s := app.settings()

	clients, _ := app.kumaRegistry.All()
	npmClients, _ := app.npmRegistry.All()

	degraded := false
	var reasons []string

	enabledKuma, _ := app.database.GetEnabledKumaInstances()
	if len(enabledKuma) > 0 && len(clients) == 0 {
		degraded = true
		reasons = append(reasons, "no Kuma instances reachable")
	}
	enabledNPM, _ := app.database.GetEnabledNPMInstances()
	if len(enabledNPM) > 0 && len(npmClients) == 0 {
		degraded = true
		reasons = append(reasons, "no NPM instances reachable")
	}

	npmNameMap := make(map[int]string)
	for _, inst := range enabledNPM {
		npmNameMap[int(inst.ID)] = inst.Name
	}

	var dockerItems, npmItems []notify.Item
	if !degraded {
		services, sErr := synclib.GetDockerServicesWithStatus(s.ComposePath, clients)
		if sErr != nil {
			degraded = true
			reasons = append(reasons, fmt.Sprintf("compose load failed: %v", sErr))
		}
		proxies, pErr := synclib.GetNPMProxiesWithStatus(npmClients, clients)
		if pErr != nil {
			degraded = true
			reasons = append(reasons, fmt.Sprintf("NPM proxy fetch failed: %v", pErr))
		}
		if sErr == nil && pErr == nil {
			links, lerr := app.database.GetServiceLinks()
			if lerr != nil {
				logging.LogWarn("notify", "Failed to load service links for coverage",
					slog.String("error", lerr.Error()))
			}
			dockerItems, npmItems = buildMissingItems(services, proxies, links, npmNameMap)
		} else if sErr == nil {
			// Services loaded but proxies failed: report docker items without link coverage.
			for _, svc := range services {
				dockerItems = append(dockerItems, notify.Item{Name: svc.ContainerName, InKuma: svc.InKuma})
			}
		}
	}

	report := notify.ComputeMissing(dockerItems, npmItems, degraded, reasons)
	c.JSON(http.StatusOK, gin.H{
		"docker":     report.Docker,
		"npm":        report.NPM,
		"fetched_at": report.FetchedAt,
		"degraded":   report.Degraded,
		"reasons":    report.Reasons,
	})
}

func (app *App) ProgressSSE(c *gin.Context) {
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.String(http.StatusInternalServerError, "streaming unsupported")
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	ch := make(chan synclib.Progress, 16)

	app.mu.Lock()
	app.progressChans = append(app.progressChans, ch)
	app.mu.Unlock()

	defer func() {
		app.mu.Lock()
		for i, c_ := range app.progressChans {
			if c_ == ch {
				app.progressChans = append(app.progressChans[:i], app.progressChans[i+1:]...)
				break
			}
		}
		app.mu.Unlock()
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Fprintf(c.Writer, ": keepalive\n\n")
			flusher.Flush()
		case p, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(p)
			fmt.Fprintf(c.Writer, "data: %s\n\n", data)
			flusher.Flush()
			if strings.Contains(p.Status, "completed") || p.Status == "error" {
				ticker.Stop()
			}
		}
	}
}

// ─── Logs API ────────────────────────────────────────────────────────────────

// LogsHandler returns filtered log entries from the in-memory buffer.
// Supports query params: level, source, search, limit, offset.
func (app *App) LogsHandler(c *gin.Context) {
	level := c.Query("level")
	source := c.Query("source")
	search := c.Query("search")
	errorKind := c.Query("error_kind")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	entries := logging.DefaultBuffer().Filter(logging.FilterParams{
		Level:     level,
		Source:    source,
		Search:    search,
		ErrorKind: errorKind,
		Limit:     limit,
		Offset:    offset,
	})

	if entries == nil {
		entries = []logging.Entry{}
	}

	c.JSON(http.StatusOK, entries)
}

// LogsStreamSSE streams new log entries in real-time via SSE.
func (app *App) LogsStreamSSE(c *gin.Context) {
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.String(http.StatusInternalServerError, "streaming unsupported")
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	ch := logging.Subscribe()
	defer logging.Unsubscribe(ch)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Fprintf(c.Writer, ": keepalive\n\n")
			flusher.Flush()
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(c.Writer, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ─── Authelia Handlers ──────────────────────────────────────────────────────

// resolveNPMEntries fetches NPM proxy entries for the given npm_instance_ids JSON array.
// If the array is empty or "[]", it fetches from all NPM instances.
func (app *App) resolveNPMEntries(npmInstanceIDs string) []npm.ProxyEntry {
	var ids []int
	json.Unmarshal([]byte(npmInstanceIDs), &ids)

	var allEntries []npm.ProxyEntry
	if len(ids) == 0 {
		// Use all NPM instances
		clients, err := app.npmRegistry.All()
		if err != nil {
			return allEntries
		}
		for _, c := range clients {
			entries, err := c.Client.GetProxyHosts()
			if err != nil {
				continue
			}
			allEntries = append(allEntries, entries...)
		}
		return allEntries
	}
	// Use specific NPM instances
	for _, id := range ids {
		client, err := app.npmRegistry.Get(id)
		if err != nil {
			continue
		}
		entries, err := client.GetProxyHosts()
		if err != nil {
			continue
		}
		allEntries = append(allEntries, entries...)
	}
	return allEntries
}

// composeAutheliaEntries returns compose-derived Authelia entries for the
// configured compose path. On read failure it logs a warning and returns nil
// so sync degrades to NPM-only (spec: Compose path unreadable).
func (app *App) composeAutheliaEntries() []npm.ProxyEntry {
	s := app.settings()
	if s.ComposePath == "" {
		return nil
	}
	services, err := synclib.LoadServices(s.ComposePath)
	if err != nil {
		logging.LogWarn("app", "compose path unreadable, continuing with NPM entries only",
			slog.String("compose_path", s.ComposePath),
			slog.String("error", err.Error()),
		)
		return nil
	}
	return synclib.ComposeAutheliaEntries(services)
}

// AutheliaStatus returns the current state of Authelia integration.
// Accepts optional ?instance_id=:id to scope to a single instance.
func (app *App) AutheliaStatus(c *gin.Context) {
	instanceID, _ := strconv.ParseInt(c.Query("instance_id"), 10, 64)

	if instanceID > 0 {
		// Scoped status for a specific instance
		inst, err := app.database.GetAutheliaInstance(instanceID)
		if err != nil || inst == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "authelia instance not found"})
			return
		}
		app.buildAutheliaInstanceStatus(c, inst)
		return
	}

	// Aggregate status across all enabled instances
	s := app.settings()
	if s.AutheliaConfigPath == "" {
		// Check if there are any authelia instances configured
		instances, err := app.database.GetEnabledAutheliaInstances()
		if err != nil || len(instances) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"configured": false,
				"message":    "No Authelia instances configured",
			})
			return
		}
		// Return aggregate: domains across all instances
		var allDomains []string
		var allNPMLists []string
		for _, inst := range instances {
			ac, err := authelia.ParseConfig(inst.ConfigPath)
			if err != nil {
				continue
			}
			allDomains = append(allDomains, authelia.GetDomains(ac)...)
			npmEntries := app.resolveNPMEntries(inst.NPMInstanceIDs)
			for _, e := range npmEntries {
				allNPMLists = append(allNPMLists, e.CNAME)
			}
		}
		for _, e := range app.composeAutheliaEntries() {
			allNPMLists = append(allNPMLists, e.CNAME)
		}
		matched, missing := authelia.CompareCNAMEs(allNPMLists, allDomains)
		c.JSON(http.StatusOK, gin.H{
			"configured":     true,
			"domains":        allDomains,
			"npm_cnames":     allNPMLists,
			"matched":        matched,
			"missing":        missing,
			"instance_count": len(instances),
		})
		return
	}

	// Legacy fallback (single instance from settings)
	ac, err := authelia.ParseConfig(s.AutheliaConfigPath)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"configured": true,
			"error":      err.Error(),
			"domains":    []string{},
		})
		return
	}

	autheliaDomains := authelia.GetDomains(ac)

	var npmCNAMEs []string
	clients, _ := app.kumaRegistry.All()
	npmClients, _ := app.npmRegistry.All()
	proxies, npmErr := synclib.GetNPMProxiesWithStatus(npmClients, clients)
	if npmErr != nil {
		// Partial failure: use whatever was fetched, log the aggregate error.
		logging.LogError("app", "Partial NPM proxy fetch failure in Authelia status",
			slog.String("error", npmErr.Error()),
		)
	}
	for _, p := range proxies {
		npmCNAMEs = append(npmCNAMEs, p.CNAME)
	}
	for _, e := range app.composeAutheliaEntries() {
		npmCNAMEs = append(npmCNAMEs, e.CNAME)
	}

	matched, missing := authelia.CompareCNAMEs(npmCNAMEs, autheliaDomains)

	openAlerts := 0
	if alerts, err := app.database.GetOpenAutheliaAlerts(0); err == nil {
		openAlerts = len(alerts)
	}

	c.JSON(http.StatusOK, gin.H{
		"configured":     true,
		"domains":        autheliaDomains,
		"npm_cnames":     npmCNAMEs,
		"matched":        matched,
		"missing":        missing,
		"open_alerts":    openAlerts,
		"sync_enabled":   s.AutheliaSyncEnabled,
		"default_policy": s.AutheliaDefaultPolicy,
		"npm_error":      npmErr != nil,
		"npm_error_msg": func() string {
			if npmErr != nil {
				return npmErr.Error()
			}
			return ""
		}(),
	})
}

// buildAutheliaInstanceStatus builds a status response for a single Authelia instance.
func (app *App) buildAutheliaInstanceStatus(c *gin.Context, inst *db.AutheliaInstance) {
	ac, err := authelia.ParseConfig(inst.ConfigPath)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"configured":    true,
			"instance_id":   inst.ID,
			"instance_name": inst.Name,
			"error":         err.Error(),
			"domains":       []string{},
		})
		return
	}

	autheliaDomains := authelia.GetDomains(ac)
	npmEntries := app.resolveNPMEntries(inst.NPMInstanceIDs)
	var npmCNAMEs []string
	for _, e := range npmEntries {
		npmCNAMEs = append(npmCNAMEs, e.CNAME)
	}
	for _, e := range app.composeAutheliaEntries() {
		npmCNAMEs = append(npmCNAMEs, e.CNAME)
	}

	matched, missing := authelia.CompareCNAMEs(npmCNAMEs, autheliaDomains)

	openAlerts := 0
	if alerts, err := app.database.GetOpenAutheliaAlerts(inst.ID); err == nil {
		openAlerts = len(alerts)
	}

	c.JSON(http.StatusOK, gin.H{
		"configured":     true,
		"instance_id":    inst.ID,
		"instance_name":  inst.Name,
		"domains":        autheliaDomains,
		"npm_cnames":     npmCNAMEs,
		"matched":        matched,
		"missing":        missing,
		"open_alerts":    openAlerts,
		"sync_enabled":   inst.AutoSync,
		"default_policy": inst.DefaultPolicy,
	})
}

// AutheliaCoverage reports per-instance coverage of compose-derived service
// domains in Authelia access_control rules. Returns an empty list when the
// compose path is unreadable.
func (app *App) AutheliaCoverage(c *gin.Context) {
	instances, err := app.database.GetEnabledAutheliaInstances()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	services, cerr := synclib.LoadServices(app.settings().ComposePath)
	if cerr != nil {
		logging.LogWarn("app", "compose path unreadable, no Authelia coverage data",
			slog.String("error", cerr.Error()),
		)
		c.JSON(http.StatusOK, gin.H{"instances": []any{}})
		return
	}
	composeDomains := synclib.ComposeAutheliaEntries(services)

	type domainCoverage struct {
		Domain  string `json:"domain"`
		Service string `json:"service"`
		Covered bool   `json:"covered"`
		Policy  string `json:"policy"`
	}
	type instanceCoverage struct {
		InstanceID   int64            `json:"instance_id"`
		InstanceName string           `json:"instance_name"`
		Domains      []domainCoverage `json:"domains"`
	}

	result := make([]instanceCoverage, 0, len(instances))
	for _, inst := range instances {
		ac, aerr := authelia.ParseConfig(inst.ConfigPath)
		if aerr != nil {
			continue
		}
		var overrides map[string]string
		if inst.Overrides != "" && inst.Overrides != "{}" {
			json.Unmarshal([]byte(inst.Overrides), &overrides)
		}
		policy := inst.DefaultPolicy
		if policy == "" {
			policy = authelia.DefaultPolicy
		}
		existingDomains := authelia.GetDomains(ac)

		domains := make([]domainCoverage, 0, len(composeDomains))
		for _, e := range composeDomains {
			p := policy
			if ov, ok := overrides[e.CNAME]; ok && ov != "" {
				p = ov
			}
			domains = append(domains, domainCoverage{
				Domain:  e.CNAME,
				Service: e.Container,
				Covered: authelia.DomainMatches(e.CNAME, existingDomains) != "",
				Policy:  p,
			})
		}
		result = append(result, instanceCoverage{
			InstanceID:   inst.ID,
			InstanceName: inst.Name,
			Domains:      domains,
		})
	}
	c.JSON(http.StatusOK, gin.H{"instances": result})
}

// AutheliaAlerts returns all authelia alerts.
func (app *App) AutheliaAlerts(c *gin.Context) {
	logging.LogDebug("authelia", "Alerts requested")
	instanceID, _ := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	alerts, err := app.database.GetAutheliaAlerts(instanceID)
	if err != nil {
		logging.LogError("authelia", "Failed to fetch alerts",
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if alerts == nil {
		alerts = []db.AutheliaAlert{}
	}
	logging.LogInfo("authelia", "Alerts fetched",
		slog.Int("alert_count", len(alerts)),
	)
	c.JSON(http.StatusOK, alerts)
}

// AutheliaResolveAlert marks an authelia alert as resolved.
func (app *App) AutheliaResolveAlert(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.LogError("authelia", "Invalid alert ID",
			slog.String("id_str", idStr),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	logging.LogInfo("authelia", "Resolving alert",
		slog.Int64("alert_id", id),
	)
	if err := app.database.ResolveAutheliaAlert(id); err != nil {
		logging.LogError("authelia", "Failed to resolve alert",
			slog.Int64("alert_id", id),
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logging.LogInfo("authelia", "Alert resolved",
		slog.Int64("alert_id", id),
	)
	c.JSON(http.StatusOK, gin.H{"status": "resolved"})
}

// AutheliaTempAccess returns all temporary IP access rules.
func (app *App) AutheliaTempAccess(c *gin.Context) {
	logging.LogDebug("authelia", "Temp access rules requested")
	// Clean up expired rules first
	logging.LogDebug("authelia", "Cleaning up expired temp access rules")
	if err := app.database.CleanupExpiredTempAccess(); err != nil {
		logging.LogError("authelia", "Failed to clean up expired temp access",
			slog.String("error", err.Error()),
		)
	}

	instanceID, _ := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	rules, err := app.database.GetTempAccessRules(instanceID)
	if err != nil {
		logging.LogError("authelia", "Failed to fetch temp access rules",
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []db.TempAccess{}
	}
	c.JSON(http.StatusOK, rules)
}

// AutheliaAddTempAccess creates a new temporary IP access rule.
func (app *App) AutheliaAddTempAccess(c *gin.Context) {
	var input struct {
		IP        string `json:"ip"`
		Reason    string `json:"reason"`
		Duration  string `json:"duration"`   // Go duration string (e.g., "24h", "7d")
		ExpiresAt string `json:"expires_at"` // RFC3339 timestamp (alternative to duration)
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		logging.LogError("authelia", "Invalid temp access request",
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if input.IP == "" {
		logging.LogError("authelia", "Temp access missing IP")
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	var expiresAt time.Time

	if input.ExpiresAt != "" {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, input.ExpiresAt)
		if err != nil {
			logging.LogError("authelia", "Invalid expires_at format",
				slog.String("expires_at", input.ExpiresAt),
			)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid expires_at format, use RFC3339"})
			return
		}
	} else if input.Duration != "" {
		d, err := time.ParseDuration(input.Duration)
		if err != nil {
			logging.LogError("authelia", "Invalid duration format",
				slog.String("duration", input.Duration),
			)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid duration: " + err.Error()})
			return
		}
		expiresAt = time.Now().Add(d)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "duration or expires_at is required"})
		return
	}

	rule := &db.TempAccess{
		IP:        input.IP,
		Reason:    input.Reason,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := app.database.AddTempAccess(rule); err != nil {
		logging.LogError("authelia", "Failed to create temp access",
			slog.String("ip", input.IP),
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logging.LogInfo("authelia", "Temp access created",
		slog.String("ip", input.IP),
		slog.String("reason", input.Reason),
		slog.Time("expires_at", expiresAt),
	)
	c.JSON(http.StatusOK, gin.H{"status": "created"})
}

// AutheliaRevokeTempAccess revokes a temporary IP access rule.
func (app *App) AutheliaRevokeTempAccess(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logging.LogError("authelia", "Invalid temp access ID",
			slog.String("id_str", idStr),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	logging.LogInfo("authelia", "Revoking temp access",
		slog.Int64("rule_id", id),
	)
	if err := app.database.RevokeTempAccess(id); err != nil {
		logging.LogError("authelia", "Failed to revoke temp access",
			slog.Int64("rule_id", id),
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logging.LogInfo("authelia", "Temp access revoked",
		slog.Int64("rule_id", id),
	)
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// AutheliaSync runs an Authelia sync operation (dry-run or actual).
// Accepts optional ?instance_id=:id to scope to a single instance.
// Request body can include:
//   - dry_run: bool (default: true for safety)
func (app *App) AutheliaSync(c *gin.Context) {
	start := time.Now()
	instanceID, _ := strconv.ParseInt(c.Query("instance_id"), 10, 64)

	var input struct {
		DryRun *bool `json:"dry_run"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		// Use defaults on parse error
	}
	dryRun := true
	if input.DryRun != nil {
		dryRun = *input.DryRun
	}

	if instanceID > 0 {
		// Sync a single instance
		inst, err := app.database.GetAutheliaInstance(instanceID)
		if err != nil || inst == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "authelia instance not found"})
			return
		}
		app.syncAutheliaInstance(c, inst, dryRun, start)
		return
	}

	// Sync all enabled instances (or fall back to legacy settings)
	s := app.settings()
	instances, err := app.database.GetEnabledAutheliaInstances()
	if err == nil && len(instances) > 0 {
		// Use new multi-instance path
		var allResults []gin.H
		for _, inst := range instances {
			result := app.syncAutheliaInstanceInternal(&inst, dryRun)
			allResults = append(allResults, result)
		}
		logging.LogInfo("authelia", "Authelia sync complete",
			slog.Int("instance_count", len(allResults)),
			slog.Duration("duration", time.Since(start)),
		)
		c.JSON(http.StatusOK, gin.H{
			"dry_run":   dryRun,
			"instances": allResults,
			"message":   fmt.Sprintf("Synced %d Authelia instance(s)", len(instances)),
		})
		return
	}

	// Legacy fallback (single instance from settings)
	if s.AutheliaConfigPath == "" {
		logging.LogError("authelia", "Authelia sync failed — no instances configured")
		c.JSON(http.StatusBadRequest, gin.H{"error": "No Authelia instances configured"})
		return
	}

	npmClients, _ := app.npmRegistry.All()
	npmEntries, err := synclib.GetNPMProxyEntries(npmClients)
	if err != nil && len(npmEntries) == 0 {
		// All instances failed — nothing to sync.
		logging.LogError("authelia", "Failed to fetch NPM entries for Authelia sync",
			slog.String("error", err.Error()),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch NPM entries: " + err.Error()})
		return
	}
	if err != nil {
		// Partial failure: proceed with the entries we have.
		logging.LogError("authelia", "Partial NPM fetch failure during Authelia sync",
			slog.String("error", err.Error()),
		)
	}
	npmEntries = append(npmEntries, app.composeAutheliaEntries()...)

	var overrides map[string]string
	if s.AutheliaSyncOverrides != "" {
		json.Unmarshal([]byte(s.AutheliaSyncOverrides), &overrides)
	}

	actions, err := authelia.SyncConfig(s.AutheliaConfigPath, s.AutheliaDBPath, npmEntries, s.AutheliaDefaultPolicy, overrides, s.AutheliaSyncEnabled, dryRun)
	if err != nil {
		logging.LogError("authelia", "Authelia sync config failed",
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "actions": actions})
		return
	}

	if !dryRun && s.AutheliaSyncEnabled {
		for _, a := range actions {
			if a.Action == "add" {
				app.database.AddAutheliaAlert(&db.AutheliaAlert{
					CNAME:     a.CNAME,
					Message:   a.Message,
					Severity:  "info",
					Status:    "resolved",
					CreatedAt: time.Now(),
				})
			}
		}
	}

	if !s.AutheliaSyncEnabled {
		for _, a := range actions {
			if a.Action == "alert" {
				app.database.AddAutheliaAlert(&db.AutheliaAlert{
					CNAME:     a.CNAME,
					Message:   a.Message,
					Severity:  "warning",
					CreatedAt: time.Now(),
				})
			}
		}
	}

	added, skipped, alerted := countActions(actions)
	logging.LogInfo("authelia", "Authelia sync complete",
		slog.Int("actions", len(actions)),
		slog.Int("added", added),
		slog.Int("skipped", skipped),
		slog.Int("alerted", alerted),
		slog.Bool("dry_run", dryRun),
		slog.Duration("duration", time.Since(start)),
	)
	c.JSON(http.StatusOK, gin.H{
		"dry_run": dryRun, "actions": actions,
		"added": added, "skipped": skipped, "alerted": alerted,
	})
}

// syncAutheliaInstance syncs a single Authelia instance and returns the HTTP response.
func (app *App) syncAutheliaInstance(c *gin.Context, inst *db.AutheliaInstance, dryRun bool, start time.Time) {
	npmEntries := app.resolveNPMEntries(inst.NPMInstanceIDs)
	npmEntries = append(npmEntries, app.composeAutheliaEntries()...)

	var overrides map[string]string
	if inst.Overrides != "" && inst.Overrides != "{}" {
		json.Unmarshal([]byte(inst.Overrides), &overrides)
	}

	actions, err := authelia.SyncConfig(inst.ConfigPath, inst.DBPath, npmEntries, inst.DefaultPolicy, overrides, inst.AutoSync, dryRun)
	if err != nil {
		logging.LogError("authelia", "Authelia sync config failed",
			slog.Int64("instance_id", inst.ID),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "actions": actions, "instance_id": inst.ID})
		return
	}

	// Create alerts for this instance
	if !dryRun && inst.AutoSync {
		for _, a := range actions {
			if a.Action == "add" {
				app.database.AddAutheliaAlert(&db.AutheliaAlert{
					CNAME:              a.CNAME,
					Message:            a.Message,
					Severity:           "info",
					Status:             "resolved",
					CreatedAt:          time.Now(),
					AutheliaInstanceID: inst.ID,
				})
			}
		}
	}

	if !inst.AutoSync {
		for _, a := range actions {
			if a.Action == "alert" {
				app.database.AddAutheliaAlert(&db.AutheliaAlert{
					CNAME:              a.CNAME,
					Message:            a.Message,
					Severity:           "warning",
					CreatedAt:          time.Now(),
					AutheliaInstanceID: inst.ID,
				})
			}
		}
	}

	added, skipped, alerted := countActions(actions)
	logging.LogInfo("authelia", "Authelia sync instance complete",
		slog.Int64("instance_id", inst.ID),
		slog.Int("added", added),
		slog.Int("skipped", skipped),
		slog.Int("alerted", alerted),
		slog.Duration("duration", time.Since(start)),
	)
	c.JSON(http.StatusOK, gin.H{
		"dry_run": dryRun, "actions": actions,
		"added": added, "skipped": skipped, "alerted": alerted,
		"instance_id": inst.ID, "instance_name": inst.Name,
	})
}

// syncAutheliaInstanceInternal runs a sync for a single instance without writing an HTTP response.
func (app *App) syncAutheliaInstanceInternal(inst *db.AutheliaInstance, dryRun bool) gin.H {
	npmEntries := app.resolveNPMEntries(inst.NPMInstanceIDs)
	npmEntries = append(npmEntries, app.composeAutheliaEntries()...)

	var overrides map[string]string
	if inst.Overrides != "" && inst.Overrides != "{}" {
		json.Unmarshal([]byte(inst.Overrides), &overrides)
	}

	actions, err := authelia.SyncConfig(inst.ConfigPath, inst.DBPath, npmEntries, inst.DefaultPolicy, overrides, inst.AutoSync, dryRun)
	if err != nil {
		return gin.H{"instance_id": inst.ID, "instance_name": inst.Name, "error": err.Error()}
	}

	if !dryRun && inst.AutoSync {
		for _, a := range actions {
			if a.Action == "add" {
				app.database.AddAutheliaAlert(&db.AutheliaAlert{
					CNAME:              a.CNAME,
					Message:            a.Message,
					Severity:           "info",
					Status:             "resolved",
					CreatedAt:          time.Now(),
					AutheliaInstanceID: inst.ID,
				})
			}
		}
	}

	if !inst.AutoSync {
		for _, a := range actions {
			if a.Action == "alert" {
				app.database.AddAutheliaAlert(&db.AutheliaAlert{
					CNAME:              a.CNAME,
					Message:            a.Message,
					Severity:           "warning",
					CreatedAt:          time.Now(),
					AutheliaInstanceID: inst.ID,
				})
			}
		}
	}

	added, skipped, alerted := countActions(actions)
	return gin.H{
		"instance_id": inst.ID, "instance_name": inst.Name,
		"actions": actions, "added": added, "skipped": skipped, "alerted": alerted,
	}
}

// countActions tallies add/skip/alert actions.
func countActions(actions []authelia.SyncAction) (added, skipped, alerted int) {
	for _, a := range actions {
		switch a.Action {
		case "add":
			added++
		case "skip":
			skipped++
		case "alert":
			alerted++
		}
	}
	return
}
