package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"synapse/internal/db"
	"synapse/internal/docker"
	"synapse/internal/kuma"
	"synapse/internal/npm"
	synclib "synapse/internal/sync"
)

func setupTest(t *testing.T) (*App, *gin.Engine) {
	t.Setenv("COMPOSE_PATH", "testdata/docker-compose.yml")
	t.Setenv("NPM_HOST", "http://localhost:81")
	t.Setenv("NPM_USER", "admin")
	t.Setenv("NPM_PASS", "")
	t.Setenv("KUMA_URL", "http://localhost:3001")
	t.Setenv("KUMA_USER", "admin")
	t.Setenv("KUMA_PASS", "")

	tmpDB := t.TempDir() + "/test.db"
	database, err := db.Open(tmpDB)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	app := &App{
		database:     database,
		kumaRegistry: kuma.NewRegistry(database),
		npmRegistry:  npm.NewRegistry(database),
	}
	r := setupRouter(app)
	return app, r
}

// testTokens maps sessionID -> bearer secret so authRequest can attach the
// token automatically for mutation requests. Keeps existing mutation tests
// working now that mutations require a bearer token.
var (
	testTokens   = map[string]string{}
	testTokensMu sync.Mutex
)

func createTestSession(t *testing.T, app *App) string {
	sessionID, userID := createTestSessionRaw(t, app)
	// Provision a bearer token for this session so mutation tests work.
	secret := generateAPIToken()
	if _, err := app.database.CreateAPIToken(userID, "test", hashToken(secret), nil); err != nil {
		t.Fatalf("create token: %v", err)
	}
	testTokensMu.Lock()
	testTokens[sessionID] = secret
	testTokensMu.Unlock()
	return sessionID
}

// createTestSessionRaw creates an admin user and a session without provisioning
// a bearer token. Used by security tests that exercise missing/invalid tokens.
func createTestSessionRaw(t *testing.T, app *App) (string, int64) {
	userID, err := app.database.CreateAdminUser("admin", "$2a$10$dummyhashnotusedfortest")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	sessionID := generateSessionID()
	sessionStoreMu.Lock()
	sessionStore[sessionID] = sessionInfo{Expiry: time.Now().Add(1 * time.Hour), UserID: userID}
	sessionStoreMu.Unlock()
	return sessionID, userID
}

// createTestUser creates a user with a distinct username and returns a session
// for them, without provisioning a bearer token.
func createTestUser(t *testing.T, app *App, username string) (string, int64) {
	userID, err := app.database.CreateAdminUser(username, "$2a$10$dummyhashnotusedfortest")
	if err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	sessionID := generateSessionID()
	sessionStoreMu.Lock()
	sessionStore[sessionID] = sessionInfo{Expiry: time.Now().Add(1 * time.Hour), UserID: userID}
	sessionStoreMu.Unlock()
	return sessionID, userID
}

func authRequest(t *testing.T, method, path string, body string, sessionID string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
		testTokensMu.Lock()
		tok := testTokens[sessionID]
		testTokensMu.Unlock()
		if tok != "" && method != "GET" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	return req
}

// authRequestNoToken builds a session-authenticated request without a bearer
// token, for security tests asserting that mutations reject missing tokens.
func authRequestNoToken(t *testing.T, method, path string, body string, sessionID string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	}
	return req
}

// authRequestWithToken builds a request with an explicit bearer token.
func authRequestWithToken(t *testing.T, method, path string, body string, sessionID string, token string) *http.Request {
	req := authRequestNoToken(t, method, path, body, sessionID)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestCheckSetup_NoAdmin(t *testing.T) {
	_, r := setupTest(t)
	req := httptest.NewRequest("GET", "/api/check-setup", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["setup"] != false {
		t.Errorf("expected setup=false, got %v", body["setup"])
	}
}

func TestCheckSetup_WithAdmin(t *testing.T) {
	app, r := setupTest(t)
	createTestSession(t, app)

	req := httptest.NewRequest("GET", "/api/check-setup", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["setup"] != true {
		t.Errorf("expected setup=true, got %v", body["setup"])
	}
}

func TestSetupLogin_CreatesAdmin(t *testing.T) {
	app, r := setupTest(t)
	t.Cleanup(func() {}) // app already cleaned up

	body := `{"username":"admin","password":"testpassword123","setup":true}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	count, err := app.database.CountAdminUsers()
	if err != nil {
		t.Fatalf("count admin users: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 admin user, got %d", count)
	}
}

func TestSetupLogin_ShortPassword(t *testing.T) {
	_, r := setupTest(t)

	body := `{"username":"admin","password":"short","setup":true}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestSetupLogin_AlreadySetup(t *testing.T) {
	app, r := setupTest(t)
	createTestSession(t, app)

	body := `{"username":"admin2","password":"testpassword123","setup":true}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	app, r := setupTest(t)
	_, err := app.database.CreateAdminUser("admin", "$2a$10$dummyhas")
	if err != nil {
		// Just proceed - the login flow will handle missing user gracefully
	}

	body := `{"username":"admin","password":"wrongpassword"}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLogin_Successful(t *testing.T) {
	app, r := setupTest(t)

	// Create admin with known password hash
	hash, err := bcrypt.GenerateFromPassword([]byte("correctpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, err = app.database.CreateAdminUser("admin", string(hash))
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	body := `{"username":"admin","password":"correctpass"}`
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_RequiresAuth(t *testing.T) {
	_, r := setupTest(t)

	endpoints := []string{
		"/api/status",
		"/api/settings",
		"/api/sync/history",
		"/api/monitors",
		"/api/monitors/1/stats",
		"/api/npm-instances",
		"/api/authelia/status",
		"/api/authelia/alerts",
		"/api/authelia/temp-access",
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", ep, w.Code)
		}
	}
}

func TestLogout(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "POST", "/api/logout", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Session should be invalidated
	req2 := httptest.NewRequest("GET", "/api/status", nil)
	req2.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after logout, got %d", w2.Code)
	}
}

func TestStatusEndpoint(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "GET", "/api/status", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if _, ok := body["docker_count"]; !ok {
		t.Error("missing docker_count")
	}
	if _, ok := body["monitor_count"]; !ok {
		t.Error("missing monitor_count")
	}
}

func TestSyncHistoryEmpty(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "GET", "/api/sync/history", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("expected empty array, got %d items", len(body))
	}
}

func TestDashboard(t *testing.T) {
	app, r := setupTest(t)
	createTestSession(t, app)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestSettingsEndpoint(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// GET settings returns defaults
	req := authRequest(t, "GET", "/api/settings", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var settings map[string]any
	json.NewDecoder(w.Body).Decode(&settings)
	// kuma_* settings moved to the /api/kuma-instances endpoints and are
	// no longer part of the settings response.
	if _, ok := settings["kuma_url"]; ok {
		t.Errorf("kuma_url should not be in settings response, got %v", settings["kuma_url"])
	}
	if settings["npm_pass"] != "" {
		t.Errorf("expected empty npm_pass, got %v", settings["npm_pass"])
	}
}

func TestSettingsSaveAndLoad(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// npm_host is now managed via /api/npm-instances; compose_path is still managed via /api/settings
	body := `{"compose_path":"/data/compose.yml"}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("post settings: expected 200, got %d", w.Code)
	}

	// GET should return saved compose_path only
	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s2 map[string]any
	json.NewDecoder(w2.Body).Decode(&s2)
	if s2["compose_path"] != "/data/compose.yml" {
		t.Errorf("expected saved compose_path, got %v", s2["compose_path"])
	}
}

func TestSaveSettingsOnlySentFields(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Save compose_path first via direct DB
	if err := app.database.SaveSettingsMap(map[string]string{
		"compose_path": "/docker/compose.yml",
	}); err != nil {
		t.Fatalf("seed compose_path: %v", err)
	}

	// POST settings with ONLY otel_enabled — compose_path should NOT be affected
	body := `{"otel_enabled":true}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("post settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// GET settings and verify only sent fields changed
	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s map[string]any
	json.NewDecoder(w2.Body).Decode(&s)

	if s["compose_path"] != "/docker/compose.yml" {
		t.Errorf("compose_path should be preserved: expected %q, got %v", "/docker/compose.yml", s["compose_path"])
	}
	if s["otel_enabled"] != true {
		t.Errorf("otel_enabled should be true: got %v", s["otel_enabled"])
	}
}

func TestEinkEnabledSaveAndLoad(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Default: eink_enabled should be false
	req0 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w0 := httptest.NewRecorder()
	r.ServeHTTP(w0, req0)
	var s0 map[string]any
	json.NewDecoder(w0.Body).Decode(&s0)
	if s0["eink_enabled"] != false {
		t.Errorf("default eink_enabled should be false: got %v", s0["eink_enabled"])
	}

	// Seed compose_path, then enable eink — compose_path must be preserved
	if err := app.database.SaveSettingsMap(map[string]string{
		"compose_path": "/docker/compose.yml",
	}); err != nil {
		t.Fatalf("seed compose_path: %v", err)
	}

	body := `{"eink_enabled":true}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("post settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s map[string]any
	json.NewDecoder(w2.Body).Decode(&s)

	if s["eink_enabled"] != true {
		t.Errorf("eink_enabled should be true after save: got %v", s["eink_enabled"])
	}
	if s["compose_path"] != "/docker/compose.yml" {
		t.Errorf("compose_path should be preserved: expected %q, got %v", "/docker/compose.yml", s["compose_path"])
	}

	// Toggle back off via only-sent-fields
	body2 := `{"eink_enabled":false}`
	req3 := authRequest(t, "POST", "/api/settings", body2, sessionID)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("post settings (off): expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	req4 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	var s4 map[string]any
	json.NewDecoder(w4.Body).Decode(&s4)
	if s4["eink_enabled"] != false {
		t.Errorf("eink_enabled should be false after toggling off: got %v", s4["eink_enabled"])
	}
	if s4["compose_path"] != "/docker/compose.yml" {
		t.Errorf("compose_path should remain preserved: expected %q, got %v", "/docker/compose.yml", s4["compose_path"])
	}
}

func TestTrmnlApiTokenSaveAndLoad(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Default: no token configured
	req0 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w0 := httptest.NewRecorder()
	r.ServeHTTP(w0, req0)
	var s0 map[string]any
	json.NewDecoder(w0.Body).Decode(&s0)
	if s0["trmnl_api_token"] != "" {
		t.Errorf("default trmnl_api_token should be empty: got %v", s0["trmnl_api_token"])
	}

	// Seed compose_path, then save a token — compose_path must be preserved
	if err := app.database.SaveSettingsMap(map[string]string{
		"compose_path": "/docker/compose.yml",
	}); err != nil {
		t.Fatalf("seed compose_path: %v", err)
	}

	body := `{"trmnl_api_token":"secret-token-123"}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("post settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s map[string]any
	json.NewDecoder(w2.Body).Decode(&s)
	if s["trmnl_api_token"] != "secret-token-123" {
		t.Errorf("trmnl_api_token should round-trip: got %v", s["trmnl_api_token"])
	}
	if s["compose_path"] != "/docker/compose.yml" {
		t.Errorf("compose_path should be preserved: expected %q, got %v", "/docker/compose.yml", s["compose_path"])
	}
}

func TestTrmnlStatsEndpoint(t *testing.T) {
	_, r := setupTest(t)

	// Public read: no credential at all → 200 + flat payload fields.
	req := httptest.NewRequest("GET", "/api/v1/trmnl/stats", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("public read: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var s map[string]any
	json.NewDecoder(w.Body).Decode(&s)
	for _, field := range []string{"docker_count", "npm_count", "monitor_count", "running", "last_docker", "last_npm", "docker_ok", "npm_ok", "kuma_ok", "up", "down"} {
		if _, ok := s[field]; !ok {
			t.Errorf("payload missing field %q: %v", field, s)
		}
	}
	if _, nested := s["connection_health"]; nested {
		t.Errorf("payload must be flat, found connection_health: %v", s)
	}

	// A stale bearer token must not change the outcome — the endpoint is
	// intentionally unauthenticated per the api-authentication spec.
	reqTok := httptest.NewRequest("GET", "/api/v1/trmnl/stats", nil)
	reqTok.Header.Set("Authorization", "Bearer whatever")
	wTok := httptest.NewRecorder()
	r.ServeHTTP(wTok, reqTok)
	if wTok.Code != http.StatusOK {
		t.Fatalf("public read with stale token: expected 200, got %d: %s", wTok.Code, wTok.Body.String())
	}
}

func TestSaveSettingsPreservesEmptyPassword(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// npm_* settings are now managed via /api/npm-instances; test that legacy fields are still readable but not writable
	if err := app.database.SaveSettingsMap(map[string]string{
		"npm_pass": "secret123",
	}); err != nil {
		t.Fatalf("seed npm_pass: %v", err)
	}

	// Legacy npm_* fields should be ignored by the settings PUT handler
	body := `{"npm_pass":"","npm_host":"http://test:81","compose_path":"/custom/path.yml"}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("post settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify compose_path was updated (still active) and npm_* were ignored
	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s map[string]any
	json.NewDecoder(w2.Body).Decode(&s)

	if s["npm_pass"] != "****" {
		t.Errorf("npm_pass should be masked and non-empty: got %v", s["npm_pass"])
	}
	if s["compose_path"] != "/custom/path.yml" {
		t.Errorf("compose_path should be updated: expected %q, got %v", "/custom/path.yml", s["compose_path"])
	}
}

func TestKumaMonitorsHandler_Empty(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "GET", "/api/monitors", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body == nil || len(body) != 0 {
		t.Errorf("expected empty array, got %v", body)
	}
}

func TestKumaMonitorStatsHandler_InvalidID(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "GET", "/api/monitors/abc/stats?instance=1", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestKumaMonitorStatsHandler_NoInstanceParam(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "GET", "/api/monitors/1/stats", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing instance param, got %d: %s", w.Code, w.Body.String())
	}
}

func TestKumaMonitorStatsHandler_NotFoundInstance(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "GET", "/api/monitors/1/stats?instance=999", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent instance, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNPMInstancesHandler_List(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Create one instance directly via DB
	if _, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "test", URL: "https://npm:81", Username: "admin", Password: "pass", Enabled: true}); err != nil {
		t.Fatalf("seed instance: %v", err)
	}

	req := authRequest(t, "GET", "/api/npm-instances", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(body))
	}
	if body[0]["name"] != "test" {
		t.Errorf("expected name=test, got %v", body[0]["name"])
	}
}

func TestNPMInstancesHandler_Create(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	body := `{"name":"new","url":"https://npm:81","username":"admin","password":"secret","enabled":true}`
	req := authRequest(t, "POST", "/api/npm-instances", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if id, ok := resp["id"].(float64); !ok || id <= 0 {
		t.Errorf("expected positive id, got %v", resp["id"])
	}
	if resp["name"] != "new" {
		t.Errorf("expected name=new, got %v", resp["name"])
	}
}

func TestNPMInstancesHandler_CreateMissingFields(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	body := `{"name":"only-name"}`
	req := authRequest(t, "POST", "/api/npm-instances", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing url, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNPMInstancesHandler_Update(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	inst, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "old", URL: "https://old:81", Username: "admin", Password: "oldpass", Enabled: true})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"name":"updated","url":"https://new:81","username":"newuser","enabled":false}`
	req := authRequest(t, "PUT", "/api/npm-instances/"+fmt.Sprintf("%d", inst.ID), body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["name"] != "updated" {
		t.Errorf("expected name=updated, got %v", resp["name"])
	}
	if resp["url"] != "https://new:81" {
		t.Errorf("expected url=https://new:81, got %v", resp["url"])
	}
}

func TestNPMInstancesHandler_UpdateNotFound(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	body := `{"name":"nope"}`
	req := authRequest(t, "PUT", "/api/npm-instances/999", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNPMInstancesHandler_Delete(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	inst, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "del", URL: "https://del:81", Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := authRequest(t, "DELETE", "/api/npm-instances/"+fmt.Sprintf("%d", inst.ID), "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "deleted" {
		t.Errorf("expected status=deleted, got %v", resp["status"])
	}

	// Verify it's gone
	req2 := authRequest(t, "GET", "/api/npm-instances", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var list []map[string]any
	json.NewDecoder(w2.Body).Decode(&list)
	if len(list) != 0 {
		t.Errorf("expected empty list after delete, got %d items", len(list))
	}
}

func TestNPMInstancesHandler_Test(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	inst, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "test", URL: "https://test:81", Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := authRequest(t, "POST", "/api/npm-instances/"+fmt.Sprintf("%d", inst.ID)+"/test", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	// NPM at localhost:81 is not running, so we expect ok=false
	if resp["ok"] != false {
		t.Logf("test result: %+v", resp)
	}
}

func TestSaveSettingsDoesNotOverwriteUnsentOtelFields(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Seed DB with otel_enabled=true
	if err := app.database.SaveSettingsMap(map[string]string{
		"otel_enabled": "true",
	}); err != nil {
		t.Fatalf("seed otel_enabled: %v", err)
	}

	// POST settings without any otel fields
	body := `{"kuma_url":"http://kuma:3001"}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("post settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// otel_enabled should still be true
	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s map[string]any
	json.NewDecoder(w2.Body).Decode(&s)

	if s["otel_enabled"] != true {
		t.Errorf("otel_enabled should remain true: got %v", s["otel_enabled"])
	}
}

func setupRouter(app *App) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	absPath, _ := filepath.Abs("static/*.html")
	if _, err := os.Stat("static/index.html"); os.IsNotExist(err) {
		absPath = filepath.Join(filepath.Dir(absPath), "../../static/*.html")
	}
	r.LoadHTMLGlob(absPath)

	r.GET("/", app.Dashboard)
	r.GET("/login", func(c *gin.Context) { c.HTML(http.StatusOK, "login.html", nil) })
	r.GET("/setup", func(c *gin.Context) { c.HTML(http.StatusOK, "setup.html", nil) })
	r.GET("/overview", app.OverviewPage)
	r.GET("/board", app.OverviewPage)
	r.GET("/api/public/overview", app.PublicOverview)
	r.GET("/api/check-setup", app.HandleCheckSetup)
	r.POST("/api/login", app.HandleLogin)
	app.registerOIDCRoutes(r)

	apiV1 := r.Group("/api/v1")
	{
		apiV1.GET("/trmnl/stats", app.TrmnlStats)
	}

	api := r.Group("/api")
	api.Use(app.authMiddleware())
	{
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

		// Mutation subgroup: session + bearer token required.
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

	return r
}

func TestKumaInstancesHandler_Test_Unreachable(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	inst, err := app.database.CreateKumaInstance(&db.KumaInstance{Name: "test", URL: "http://127.0.0.1:1", Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := authRequest(t, "POST", "/api/kuma-instances/"+fmt.Sprintf("%d", inst.ID)+"/test", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	// Instances at 127.0.0.1:1 is not running, so we expect ok=false
	if resp["ok"] != false {
		t.Logf("test result: %+v", resp)
	}
}

func TestNPMInstancesHandler_Test_2FAError(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Mock server that returns requires_2fa: true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tokens" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"requires_2fa":    true,
				"challenge_token": "challenge-jwt",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	inst, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "2fa-test", URL: srv.URL, Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := authRequest(t, "POST", "/api/npm-instances/"+fmt.Sprintf("%d", inst.ID)+"/test", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["ok"] != false {
		t.Fatalf("expected ok=false for 2FA account, got %+v", resp)
	}
	if resp["message"] == nil || resp["message"] == "" {
		t.Fatalf("expected error message for 2FA, got %+v", resp)
	}
}

func TestNotifyTest_Unconfigured(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "POST", "/api/notify/test", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["ok"] != false {
		t.Errorf("expected ok=false, got %+v", resp)
	}
}

func TestNotifyTest_Success(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	var gotPath, gotKey, gotTitle, gotMsg string
	gotPriority := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotPath = req.URL.Path
		gotKey = req.Header.Get("X-Gotify-Key")
		var body map[string]any
		json.NewDecoder(req.Body).Decode(&body)
		gotTitle, _ = body["title"].(string)
		gotMsg, _ = body["message"].(string)
		if p, ok := body["priority"].(float64); ok {
			gotPriority = int(p)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	if err := app.database.SaveSettingsMap(map[string]string{
		"gotify_url":      srv.URL,
		"gotify_token":    "app-token",
		"gotify_priority": "7",
	}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	req := authRequest(t, "POST", "/api/notify/test", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", resp)
	}
	if gotPath != "/message" {
		t.Errorf("expected POST /message, got %q", gotPath)
	}
	if gotKey != "app-token" {
		t.Errorf("expected X-Gotify-Key app-token, got %q", gotKey)
	}
	if gotPriority != 7 {
		t.Errorf("expected priority 7, got %d", gotPriority)
	}
	if gotTitle == "" || gotMsg == "" {
		t.Errorf("expected title+message in payload, got %q / %q", gotTitle, gotMsg)
	}
}

func TestNotifyEndpoints_RequireAuth(t *testing.T) {
	_, r := setupTest(t)
	for _, path := range []string{"/api/notify/test", "/api/notify/missing"} {
		method := http.MethodGet
		if strings.HasSuffix(path, "/test") {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401, got %d", path, w.Code)
		}
	}
}

func TestNotifyMissing_ReportsMissingItems(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// No Kuma/NPM instances configured and testdata compose has 5 services,
	// all of which are uncovered (no Kuma clients), so they are reported missing.
	req := authRequest(t, "GET", "/api/notify/missing", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["degraded"] != false {
		t.Errorf("expected degraded=false, got %+v", resp)
	}
	docker, ok := resp["docker"].([]any)
	if !ok || len(docker) != 6 {
		t.Errorf("expected 6 missing docker services, got %+v", resp["docker"])
	}
	if npm, ok := resp["npm"].([]any); !ok || len(npm) != 0 {
		t.Errorf("expected empty npm list, got %+v", resp["npm"])
	}
	if resp["fetched_at"] == nil || resp["fetched_at"] == "" {
		t.Errorf("expected fetched_at timestamp, got %+v", resp["fetched_at"])
	}
}

func TestNotifyMissing_DegradedWhenComposeMissing(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)
	t.Setenv("COMPOSE_PATH", "/nonexistent/docker-compose.yml")

	req := authRequest(t, "GET", "/api/notify/missing", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["degraded"] != true {
		t.Errorf("expected degraded=true, got %+v", resp)
	}
	reasons, ok := resp["reasons"].([]any)
	if !ok || len(reasons) == 0 {
		t.Errorf("expected reasons, got %+v", resp["reasons"])
	}
}

func TestSettingsRoundTrip_NotifyFields(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Seed a token, then verify it is masked in GET responses.
	if err := app.database.SaveSettingsMap(map[string]string{
		"gotify_token": "secret-token",
	}); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	// POST clamps: interval below 1 → 1, priority above 10 → 10.
	body := `{"notify_enabled":true,"notify_interval_minutes":0,"gotify_url":"http://gotify:8080","gotify_priority":99}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("post settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s map[string]any
	json.NewDecoder(w2.Body).Decode(&s)

	if s["notify_enabled"] != true {
		t.Errorf("notify_enabled: got %v", s["notify_enabled"])
	}
	if s["notify_interval_minutes"] != float64(1) {
		t.Errorf("notify_interval_minutes clamp: got %v", s["notify_interval_minutes"])
	}
	if s["gotify_priority"] != float64(10) {
		t.Errorf("gotify_priority clamp: got %v", s["gotify_priority"])
	}
	if s["gotify_url"] != "http://gotify:8080" {
		t.Errorf("gotify_url: got %v", s["gotify_url"])
	}
	if s["gotify_token"] != "****" {
		t.Errorf("gotify_token should be masked: got %v", s["gotify_token"])
	}

	// Sending "****" back must not overwrite the stored token.
	body2 := `{"gotify_token":"****"}`
	req3 := authRequest(t, "POST", "/api/settings", body2, sessionID)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("post settings (masked token): expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	req4 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	var s2 map[string]any
	json.NewDecoder(w4.Body).Decode(&s2)
	if s2["gotify_token"] != "****" {
		t.Errorf("masked token should remain stored: got %v", s2["gotify_token"])
	}
}

func TestSettingsRoundTrip_ReconcileDockerFields(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	body := `{"docker_socket":"unix:///var/run/docker.sock","docker_events_enabled":true,"docker_events_retention_days":14,"reconcile_enabled":true,"reconcile_interval_minutes":15,"reconcile_dry_run_default":false,"notify_docker_die":true,"notify_docker_health":true,"notify_docker_image":false,"notify_reconcile":true,"notify_cooldown_minutes":3}`
	req := authRequest(t, "POST", "/api/settings", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("post settings: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var s map[string]any
	json.NewDecoder(w2.Body).Decode(&s)

	if s["docker_socket"] != "unix:///var/run/docker.sock" {
		t.Errorf("docker_socket: got %v", s["docker_socket"])
	}
	if s["docker_events_enabled"] != true {
		t.Errorf("docker_events_enabled: got %v", s["docker_events_enabled"])
	}
	if s["docker_events_retention_days"] != float64(14) {
		t.Errorf("docker_events_retention_days: got %v", s["docker_events_retention_days"])
	}
	if s["reconcile_enabled"] != true {
		t.Errorf("reconcile_enabled: got %v", s["reconcile_enabled"])
	}
	if s["reconcile_interval_minutes"] != float64(15) {
		t.Errorf("reconcile_interval_minutes: got %v", s["reconcile_interval_minutes"])
	}
	if s["reconcile_dry_run_default"] != false {
		t.Errorf("reconcile_dry_run_default: got %v", s["reconcile_dry_run_default"])
	}
	if s["notify_docker_die"] != true || s["notify_docker_health"] != true || s["notify_docker_image"] != false {
		t.Errorf("notify toggles: die=%v health=%v image=%v", s["notify_docker_die"], s["notify_docker_health"], s["notify_docker_image"])
	}
	if s["notify_reconcile"] != true {
		t.Errorf("notify_reconcile: got %v", s["notify_reconcile"])
	}
	if s["notify_cooldown_minutes"] != float64(3) {
		t.Errorf("notify_cooldown_minutes: got %v", s["notify_cooldown_minutes"])
	}

	// Clamping: retention below 1 → 1, cooldown above 1440 → 1440.
	body2 := `{"docker_events_retention_days":0,"notify_cooldown_minutes":9999}`
	req3 := authRequest(t, "POST", "/api/settings", body2, sessionID)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("post settings clamp: expected 200, got %d", w3.Code)
	}
	req4 := authRequest(t, "GET", "/api/settings", "", sessionID)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	var s2 map[string]any
	json.NewDecoder(w4.Body).Decode(&s2)
	if s2["docker_events_retention_days"] != float64(1) {
		t.Errorf("retention clamp: got %v", s2["docker_events_retention_days"])
	}
	if s2["notify_cooldown_minutes"] != float64(1440) {
		t.Errorf("cooldown clamp: got %v", s2["notify_cooldown_minutes"])
	}
}

func TestReconcileEndpoint_NoLinks(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "POST", "/api/reconcile", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("reconcile: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Run struct {
			Source string `json:"source"`
			Status string `json:"status"`
			DryRun bool   `json:"dry_run"`
		} `json:"run"`
		Changes []map[string]any `json:"changes"`
		DryRun  bool             `json:"dry_run"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode reconcile response: %v", err)
	}
	if resp.Run.Source != "reconcile" {
		t.Errorf("run source: got %q", resp.Run.Source)
	}
	if resp.Run.Status != "completed" {
		t.Errorf("run status: got %q", resp.Run.Status)
	}
	// Default dry-run from settings is true.
	if !resp.Run.DryRun {
		t.Errorf("run dry_run should default to true, got %v", resp.Run.DryRun)
	}

	// The run must be persisted and visible via /api/reconcile/runs.
	req2 := authRequest(t, "GET", "/api/reconcile/runs", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var runs []db.SyncRun
	if err := json.NewDecoder(w2.Body).Decode(&runs); err != nil {
		t.Fatalf("decode runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 reconcile run, got %d", len(runs))
	}
	if runs[0].Source != "reconcile" || runs[0].Status != "completed" {
		t.Errorf("unexpected run: %+v", runs[0])
	}
}

func TestReconcileEndpoint_ExplicitApply(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "POST", "/api/reconcile", `{"dry_run":false}`, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("reconcile: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Run struct {
			DryRun bool `json:"dry_run"`
		} `json:"run"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Run.DryRun {
		t.Errorf("explicit dry_run=false should apply, run reported dry_run=true")
	}
}

func TestDockerEventsEndpoint(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	now := time.Now()
	for i, ev := range []db.DockerEvent{
		{EventType: "container", Action: "start", ActorName: "web", Image: "nginx:1.25", CreatedAt: now.Add(-time.Minute)},
		{EventType: "container", Action: "die", ActorName: "api", Image: "myapp:latest", CreatedAt: now},
		{EventType: "image", Action: "update", ActorName: "web", ImageOld: "nginx:1.25", ImageNew: "nginx:1.27", CreatedAt: now.Add(-30 * time.Second)},
	} {
		ev.ActorID = fmt.Sprintf("id%d", i)
		if err := app.database.CreateDockerEvent(&ev); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}

	// Full list, newest first.
	req := authRequest(t, "GET", "/api/docker/events", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("docker events: expected 200, got %d", w.Code)
	}
	var events []db.DockerEvent
	json.NewDecoder(w.Body).Decode(&events)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].Action != "die" {
		t.Errorf("expected newest-first ordering, first=%s", events[0].Action)
	}

	// Filter by action.
	req2 := authRequest(t, "GET", "/api/docker/events?action=die", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var dieEvents []db.DockerEvent
	json.NewDecoder(w2.Body).Decode(&dieEvents)
	if len(dieEvents) != 1 || dieEvents[0].ActorName != "api" {
		t.Fatalf("action filter: expected 1 die event for api, got %+v", dieEvents)
	}

	// Filter by container (substring).
	req3 := authRequest(t, "GET", "/api/docker/events?container=web", "", sessionID)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	var webEvents []db.DockerEvent
	json.NewDecoder(w3.Body).Decode(&webEvents)
	if len(webEvents) != 2 {
		t.Fatalf("container filter: expected 2 web events, got %d", len(webEvents))
	}

	// Invalid since → 400.
	req4 := authRequest(t, "GET", "/api/docker/events?since=garbage", "", sessionID)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusBadRequest {
		t.Errorf("invalid since: expected 400, got %d", w4.Code)
	}
}

func TestEventsFeed(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Seed a docker event (2 min ago) and a reconcile run (1 min ago).
	past := time.Now().Add(-2 * time.Minute)
	if err := app.database.CreateDockerEvent(&db.DockerEvent{
		EventType: "container", Action: "start", ActorName: "web", Image: "nginx:1.25", CreatedAt: past,
	}); err != nil {
		t.Fatalf("seed docker event: %v", err)
	}

	// Run reconcile directly to persist a run (no links → completed).
	synclib.RunReconcile(context.Background(), "testdata/docker-compose.yml", nil, nil, app.database, synclib.ReconcileOptions{DryRun: true}, nil)

	req := authRequest(t, "GET", "/api/events", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("events feed: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var items []FeedItem
	json.NewDecoder(w.Body).Decode(&items)

	kinds := map[string]int{}
	for _, it := range items {
		kinds[it.Kind]++
	}
	if kinds["docker"] < 1 {
		t.Errorf("expected docker feed item, got %+v", items)
	}
	if kinds["reconcile"] < 1 {
		t.Errorf("expected reconcile feed item, got %+v", items)
	}
	// Newest first (reconcile run happened after the docker event).
	if len(items) >= 2 && items[0].Kind != "reconcile" {
		t.Errorf("expected newest (reconcile) first, got %+v", items[0])
	}
}

func TestServicesWithContainerState(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Fake docker engine reporting one running container for the compose
	// "web" service (container name nginx-web).
	app.dockerClient = fakeDockerEngine(t, []docker.ContainerSummary{
		{ID: "abc123", Names: []string{"/nginx-web"}, Image: "nginx:1.25", State: "running", Status: "Up 2 hours"},
	})

	req := authRequest(t, "GET", "/api/services", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("services: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var services []map[string]any
	json.NewDecoder(w.Body).Decode(&services)

	var web *map[string]any
	for i := range services {
		if services[i]["container_name"] == "nginx-web" {
			web = &services[i]
			break
		}
	}
	if web == nil {
		t.Fatal("nginx-web not found in services response")
	}
	if (*web)["container_state"] != "running" {
		t.Errorf("container_state: got %v", (*web)["container_state"])
	}
	if (*web)["container_status"] != "Up 2 hours" {
		t.Errorf("container_status: got %v", (*web)["container_status"])
	}
}

func fakeDockerEngine(t *testing.T, containers []docker.ContainerSummary) *docker.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(containers)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return docker.NewWithClient(srv.URL, srv.Client())
}

// ─── Service link ensure_missing + Authelia integration tests ──────

func TestCreateServiceLink_EnsureMissing_AutoCreates(t *testing.T) {
	app, r := setupTest(t)
	t.Setenv("COMPOSE_PATH", "testdata/docker-compose-ensure-missing.yml")
	sessionID := createTestSession(t, app)

	var hosts []map[string]any
	npmSrv := mockNPMServer(t, &hosts)
	npmInst, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "npm", URL: npmSrv.URL, Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed npm: %v", err)
	}

	var monitors []kuma.KumaMonitor
	added := installKumaHooks(t, &monitors)
	kumaInst, err := app.database.CreateKumaInstance(&db.KumaInstance{Name: "kuma", URL: "http://127.0.0.1:1", Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed kuma: %v", err)
	}

	body := fmt.Sprintf(`{"service_name":"web","npm_instance_id":%d,"npm_host_name":"","kuma_instance_id":%d,"kuma_monitor_id":0,"kuma_monitor_name":"","ensure_missing":true}`,
		npmInst.ID, kumaInst.ID)
	req := authRequest(t, "POST", "/api/service-links", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	link, _ := resp["link"].(map[string]any)
	if link["npm_host_name"] != "app.example.com" {
		t.Errorf("expected npm_host_name app.example.com, got %v", link["npm_host_name"])
	}
	if link["kuma_monitor_name"] != "web" {
		t.Errorf("expected kuma_monitor_name web, got %v", link["kuma_monitor_name"])
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 created NPM host, got %d", len(hosts))
	}
	dn, _ := hosts[0]["domain_names"].([]any)
	if len(dn) != 1 || dn[0] != "app.example.com" {
		t.Errorf("expected created host domain_names [app.example.com], got %v", hosts[0]["domain_names"])
	}
	if len(*added) != 1 {
		t.Fatalf("expected 1 created Kuma monitor, got %d", len(*added))
	}
	if (*added)[0].Name != "web" || (*added)[0].Type != "http" {
		t.Errorf("expected http monitor named web, got %+v", (*added)[0])
	}
}

func TestCreateServiceLink_EnsureMissing_Off_Returns400(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	var hosts []map[string]any
	npmSrv := mockNPMServer(t, &hosts)
	npmInst, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "npm", URL: npmSrv.URL, Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed npm: %v", err)
	}

	body := fmt.Sprintf(`{"service_name":"web","npm_instance_id":%d,"npm_host_name":"missing.example.com","ensure_missing":false}`, npmInst.ID)
	req := authRequest(t, "POST", "/api/service-links", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if len(hosts) != 0 {
		t.Errorf("expected no hosts to be created, got %d", len(hosts))
	}
}

func TestCreateServiceLink_EnsureMissing_CreateFailure_502_NotPersisted(t *testing.T) {
	app, r := setupTest(t)
	t.Setenv("COMPOSE_PATH", "testdata/docker-compose-ensure-missing.yml")
	sessionID := createTestSession(t, app)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/tokens":
			fmt.Fprintf(w, `{"token":"test-token","expires":%q}`, time.Now().Add(24*time.Hour).Format(time.RFC3339))
		case r.Method == http.MethodGet && r.URL.Path == "/api/nginx/proxy-hosts":
			fmt.Fprint(w, `[]`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/nginx/proxy-hosts":
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"boom"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	npmInst, err := app.database.CreateNPMInstance(&db.NPMInstance{Name: "npm", URL: srv.URL, Username: "admin", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed npm: %v", err)
	}

	body := fmt.Sprintf(`{"service_name":"web","npm_instance_id":%d,"npm_host_name":"","ensure_missing":true}`, npmInst.ID)
	req := authRequest(t, "POST", "/api/service-links", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	// No link should have been persisted.
	req2 := authRequest(t, "GET", "/api/service-links", "", sessionID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var links []map[string]any
	if err := json.NewDecoder(w2.Body).Decode(&links); err != nil {
		t.Fatalf("decode links: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("expected no persisted links, got %d", len(links))
	}
}

func TestCreateServiceLink_Authelia_InvalidInstance_400(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	req := authRequest(t, "POST", "/api/service-links", `{"service_name":"web","authelia_instance_id":99999}`, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateServiceLink_Authelia_DryRunReturnsPlannedActions(t *testing.T) {
	app, r := setupTest(t)
	t.Setenv("COMPOSE_PATH", "testdata/docker-compose-ensure-missing.yml")
	sessionID := createTestSession(t, app)

	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	cfgContent := "access_control:\n  default_policy: two_factor\n  rules: []\n"
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	inst, err := app.database.CreateAutheliaInstance(&db.AutheliaInstance{Name: "auth", ConfigPath: cfgPath, DefaultPolicy: "two_factor", Enabled: true})
	if err != nil {
		t.Fatalf("seed authelia: %v", err)
	}

	body := fmt.Sprintf(`{"service_name":"web","authelia_instance_id":%d,"authelia_policy":"bypass","dry_run":true}`, inst.ID)
	req := authRequest(t, "POST", "/api/service-links", body, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	actions, _ := resp["authelia_actions"].([]any)
	if len(actions) != 1 {
		t.Fatalf("expected 1 authelia action, got %d: %s", len(actions), w.Body.String())
	}
	act, _ := actions[0].(map[string]any)
	if act["action"] != "add" || act["cname"] != "app.example.com" || act["policy"] != "bypass" {
		t.Errorf("unexpected action: %v", act)
	}

	// Dry run must not have written to the config file.
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(after) != cfgContent {
		t.Errorf("config file was modified by dry run:\n%s", string(after))
	}
}

func TestAutheliaCoverage_Endpoint(t *testing.T) {
	app, r := setupTest(t)
	t.Setenv("COMPOSE_PATH", "testdata/docker-compose-ensure-missing.yml")
	sessionID := createTestSession(t, app)

	dir := t.TempDir()
	coveredCfg := filepath.Join(dir, "covered.yml")
	os.WriteFile(coveredCfg, []byte("access_control:\n  default_policy: one_factor\n  rules:\n    - domain: app.example.com\n      policy: two_factor\n"), 0o644)
	missingCfg := filepath.Join(dir, "missing.yml")
	os.WriteFile(missingCfg, []byte("access_control:\n  default_policy: one_factor\n  rules: []\n"), 0o644)

	i1, err := app.database.CreateAutheliaInstance(&db.AutheliaInstance{Name: "covered", ConfigPath: coveredCfg, DefaultPolicy: "one_factor", Enabled: true})
	if err != nil {
		t.Fatalf("seed authelia: %v", err)
	}
	i2, err := app.database.CreateAutheliaInstance(&db.AutheliaInstance{Name: "missing", ConfigPath: missingCfg, DefaultPolicy: "one_factor", Enabled: true})
	if err != nil {
		t.Fatalf("seed authelia: %v", err)
	}

	req := authRequest(t, "GET", "/api/authelia/coverage", "", sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Instances []struct {
			InstanceID   int64  `json:"instance_id"`
			InstanceName string `json:"instance_name"`
			Domains      []struct {
				Domain  string `json:"domain"`
				Service string `json:"service"`
				Covered bool   `json:"covered"`
				Policy  string `json:"policy"`
			} `json:"domains"`
		} `json:"instances"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(resp.Instances))
	}
	byID := map[int64]struct {
		Covered bool
		Policy  string
	}{}
	for _, inst := range resp.Instances {
		if len(inst.Domains) != 1 {
			t.Fatalf("instance %s: expected 1 domain, got %d", inst.InstanceName, len(inst.Domains))
		}
		d := inst.Domains[0]
		if d.Domain != "app.example.com" || d.Service != "web" {
			t.Errorf("instance %s: unexpected domain entry %+v", inst.InstanceName, d)
		}
		byID[inst.InstanceID] = struct {
			Covered bool
			Policy  string
		}{d.Covered, d.Policy}
	}
	if !byID[i1.ID].Covered {
		t.Errorf("expected instance %d (covered) to report covered=true", i1.ID)
	}
	if byID[i2.ID].Covered {
		t.Errorf("expected instance %d (missing) to report covered=false", i2.ID)
	}
	if byID[i2.ID].Policy != "one_factor" {
		t.Errorf("expected missing instance policy one_factor, got %s", byID[i2.ID].Policy)
	}
}

// ---- api-authentication security tests (tasks 3.1, 3.2) ----

func TestMutations_RequireSessionAndToken(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)
	body := `{"compose_path":"/tmp/should-not-exist"}`

	// 1. Anonymous (no session, no token) → 401
	req := httptest.NewRequest("POST", "/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous mutation: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Session only, no bearer token → 401, no write
	req = authRequestNoToken(t, "POST", "/api/settings", body, sessionID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("session-only mutation: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "missing bearer token" {
		t.Errorf("session-only mutation: expected 'missing bearer token', got %q", resp["error"])
	}
	if s := app.settings(); s.ComposePath == "/tmp/should-not-exist" {
		t.Error("session-only mutation must not persist settings")
	}

	// 3. Token only, no session → 401 (authMiddleware runs before bearer check)
	testTokensMu.Lock()
	secret := testTokens[sessionID]
	testTokensMu.Unlock()
	req = authRequestWithToken(t, "POST", "/api/settings", body, "", secret)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("token-only mutation: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Malformed/unknown token → 401, no write
	req = authRequestWithToken(t, "POST", "/api/settings", body, sessionID, "not-a-real-token")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token mutation: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid bearer token" {
		t.Errorf("unknown token: expected 'invalid bearer token', got %q", resp["error"])
	}
	if s := app.settings(); s.ComposePath == "/tmp/should-not-exist" {
		t.Error("unknown-token mutation must not persist settings")
	}

	// 5. Valid session + token → 200 and setting persisted
	req = authRequest(t, "POST", "/api/settings", body, sessionID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid mutation: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if s := app.settings(); s.ComposePath != "/tmp/should-not-exist" {
		t.Errorf("expected compose_path to be persisted, got %q", s.ComposePath)
	}
}

func TestMutations_ExpiredTokenRejected(t *testing.T) {
	app, r := setupTest(t)
	sessionID, userID := createTestSessionRaw(t, app)
	body := `{"compose_path":"/tmp/expired-no-write"}`

	past := time.Now().Add(-1 * time.Hour)
	expiredSecret := "expired-secret-value"
	if _, err := app.database.CreateAPIToken(userID, "expired", hashToken(expiredSecret), &past); err != nil {
		t.Fatalf("create expired token: %v", err)
	}

	req := authRequestWithToken(t, "POST", "/api/settings", body, sessionID, expiredSecret)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired token mutation: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "token expired" {
		t.Errorf("expected 'token expired', got %q", resp["error"])
	}
	if s := app.settings(); s.ComposePath == "/tmp/expired-no-write" {
		t.Error("expired-token mutation must not persist settings")
	}
}

func TestMutations_RevokedTokenRejected(t *testing.T) {
	app, r := setupTest(t)
	sessionID, userID := createTestSessionRaw(t, app)
	body := `{"compose_path":"/tmp/revoked-no-write"}`

	revokedSecret := "revoked-secret-value"
	id, err := app.database.CreateAPIToken(userID, "revoked", hashToken(revokedSecret), nil)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := app.database.RevokeAPIToken(id); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	req := authRequestWithToken(t, "POST", "/api/settings", body, sessionID, revokedSecret)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token mutation: expected 401, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "token revoked" {
		t.Errorf("expected 'token revoked', got %q", resp["error"])
	}
	if s := app.settings(); s.ComposePath == "/tmp/revoked-no-write" {
		t.Error("revoked-token mutation must not persist settings")
	}
}

func TestTokenLifecycle_CreateListRevokeRotate(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Create
	req := authRequest(t, "POST", "/api/tokens", `{"name":"cli","expires_in_days":30}`, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create token: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == 0 || created.Token == "" || created.Name != "cli" {
		t.Fatalf("unexpected create response: %+v", created)
	}

	// List — metadata only, no secret, no hash
	req = authRequest(t, "GET", "/api/tokens", "", sessionID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list tokens: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var listed []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, tok := range listed {
		if int64(tok["id"].(float64)) == created.ID {
			found = true
			if _, hasSecret := tok["token"]; hasSecret {
				t.Error("list must not expose token secret")
			}
			if _, hasHash := tok["hash"]; hasHash {
				t.Error("list must not expose token hash")
			}
		}
	}
	if !found {
		t.Fatalf("created token %d not in list: %v", created.ID, listed)
	}

	// The created secret works for mutations
	req = authRequestWithToken(t, "POST", "/api/settings", `{"compose_path":"/tmp/token-works"}`, sessionID, created.Token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("created token mutation: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Rotate — new secret returned, old one stops working
	req = authRequest(t, "POST", fmt.Sprintf("/api/tokens/%d/rotate", created.ID), "", sessionID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate token: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var rotated struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotate: %v", err)
	}
	if rotated.Token == "" || rotated.Token == created.Token {
		t.Fatalf("rotate must return a fresh secret: %+v", rotated)
	}
	req = authRequestWithToken(t, "POST", "/api/settings", `{"compose_path":"/tmp/old-token-dead"}`, sessionID, created.Token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("old secret after rotate: expected 401, got %d", w.Code)
	}
	req = authRequestWithToken(t, "POST", "/api/settings", `{"compose_path":"/tmp/new-token-works"}`, sessionID, rotated.Token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("new secret after rotate: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Revoke — token stops working
	req = authRequest(t, "POST", fmt.Sprintf("/api/tokens/%d/revoke", created.ID), "", sessionID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke token: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	req = authRequestWithToken(t, "POST", "/api/settings", `{"compose_path":"/tmp/revoked-dead"}`, sessionID, rotated.Token)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked secret: expected 401, got %d", w.Code)
	}
}

func TestTokenLifecycle_OwnershipEnforced(t *testing.T) {
	app, r := setupTest(t)
	sessionID := createTestSession(t, app)

	// Second user owns a token; first user must not manage it.
	otherSession, otherID := createTestUser(t, app, "other")
	otherTokenID, err := app.database.CreateAPIToken(otherID, "other-token", hashToken("other-secret"), nil)
	if err != nil {
		t.Fatalf("create other token: %v", err)
	}

	for _, path := range []string{
		fmt.Sprintf("/api/tokens/%d/revoke", otherTokenID),
		fmt.Sprintf("/api/tokens/%d/rotate", otherTokenID),
	} {
		req := authRequest(t, "POST", path, "", sessionID)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: expected 403, got %d: %s", path, w.Code, w.Body.String())
		}
	}

	// The other user's token still works (not revoked/rotated by the first user).
	req := authRequestWithToken(t, "POST", "/api/settings", `{"compose_path":"/tmp/other-ok"}`, otherSession, "other-secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("other user's token after cross-user attempt: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenLifecycle_OneTimeSecret(t *testing.T) {
	app, r := setupTest(t)
	sessionID, _ := createTestSessionRaw(t, app)

	req := authRequest(t, "POST", "/api/tokens", `{"name":"onetime"}`, sessionID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create token: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Token == "" {
		t.Fatal("create must return the secret once")
	}

	// DB stores only the hash, never the plaintext secret.
	stored, err := app.database.GetAPITokenByID(created.ID)
	if err != nil || stored == nil {
		t.Fatalf("get stored token: %v", err)
	}
	if stored.Hash == created.Token {
		t.Error("DB must not store the plaintext secret")
	}
	if stored.Hash != hashToken(created.Token) {
		t.Error("DB must store the SHA-256 hash of the secret")
	}

	// The secret is not returned again by any endpoint.
	req = authRequest(t, "GET", "/api/tokens", "", sessionID)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list tokens: expected 200, got %d", w.Code)
	}
	var listed []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	for _, tok := range listed {
		if s, ok := tok["token"].(string); ok && s != "" {
			t.Error("token secret leaked in list response")
		}
		if s, ok := tok["hash"].(string); ok && s != "" {
			t.Error("token hash leaked in list response")
		}
	}

	// A second user cannot see the first user's token metadata.
	otherSession, _ := createTestUser(t, app, "other")
	req = authRequest(t, "GET", "/api/tokens", "", otherSession)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("other user list: expected 200, got %d", w.Code)
	}
	var otherList []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&otherList); err != nil {
		t.Fatalf("decode other list: %v", err)
	}
	for _, tok := range otherList {
		if int64(tok["id"].(float64)) == created.ID {
			t.Error("token metadata leaked to another user")
		}
	}
}

func TestTokenLifecycle_RequiresSession(t *testing.T) {
	_, r := setupTest(t)
	// No session → 401 on all token lifecycle endpoints.
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/tokens"},
		{"GET", "/api/tokens"},
		{"POST", "/api/tokens/1/revoke"},
		{"POST", "/api/tokens/1/rotate"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without session: expected 401, got %d", tc.method, tc.path, w.Code)
		}
	}
}

func TestPauseKumaMonitor_Success(t *testing.T) {
	app, r := setupTest(t)
	sid := createTestSession(t, app)
	inst, err := app.database.CreateKumaInstance(&db.KumaInstance{Name: "k1", URL: "http://kuma:3001", Username: "u", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	restoreVerify := kuma.SetVerifySocketIOLoginTestHook(func(url, user, pass string) error { return nil })
	defer restoreVerify()
	restore := kuma.SetPauseMonitorTestHook(func(url, user, pass string, monitorID int) error {
		if monitorID != 5 {
			t.Errorf("unexpected monitorID %d", monitorID)
		}
		return nil
	})
	defer restore()
	req := authRequest(t, "POST", fmt.Sprintf("/api/monitors/5/pause?instance=%d", inst.ID), "", sid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPauseKumaMonitor_AckFailure(t *testing.T) {
	app, r := setupTest(t)
	sid := createTestSession(t, app)
	inst, err := app.database.CreateKumaInstance(&db.KumaInstance{Name: "k1", URL: "http://kuma:3001", Username: "u", Password: "p", Enabled: true})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	restoreVerify := kuma.SetVerifySocketIOLoginTestHook(func(url, user, pass string) error { return nil })
	defer restoreVerify()
	restore := kuma.SetPauseMonitorTestHook(func(url, user, pass string, monitorID int) error {
		return fmt.Errorf("pause monitor rejected: boom")
	})
	defer restore()
	req := authRequest(t, "POST", fmt.Sprintf("/api/monitors/1/pause?instance=%d", inst.ID), "", sid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "pause monitor rejected: boom") {
		t.Fatalf("expected verbatim error, got %s", w.Body.String())
	}
}

func TestPauseKumaMonitor_InvalidID(t *testing.T) {
	app, r := setupTest(t)
	sid := createTestSession(t, app)
	req := authRequest(t, "POST", "/api/monitors/abc/pause?instance=1", "", sid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPauseKumaMonitor_MissingInstance(t *testing.T) {
	app, r := setupTest(t)
	sid := createTestSession(t, app)
	restoreVerify := kuma.SetVerifySocketIOLoginTestHook(func(url, user, pass string) error { return nil })
	defer restoreVerify()
	// no instance in DB
	req := authRequest(t, "POST", "/api/monitors/1/pause?instance=999", "", sid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResumeKumaMonitor_SuccessAndFailure(t *testing.T) {
	app, r := setupTest(t)
	sid := createTestSession(t, app)
	inst, _ := app.database.CreateKumaInstance(&db.KumaInstance{Name: "k1", URL: "http://kuma:3001", Username: "u", Password: "p", Enabled: true})
	restoreVerify := kuma.SetVerifySocketIOLoginTestHook(func(url, user, pass string) error { return nil })
	defer restoreVerify()
	restore := kuma.SetResumeMonitorTestHook(func(url, user, pass string, monitorID int) error { return nil })
	defer restore()
	req := authRequest(t, "POST", fmt.Sprintf("/api/monitors/7/resume?instance=%d", inst.ID), "", sid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	restore2 := kuma.SetResumeMonitorTestHook(func(url, user, pass string, monitorID int) error {
		return fmt.Errorf("resume monitor rejected: fail")
	})
	defer restore2()
	// need fresh restore after first defer? Use second hook overwrite
	req2 := authRequest(t, "POST", fmt.Sprintf("/api/monitors/7/resume?instance=%d", inst.ID), "", sid)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "resume monitor rejected: fail") {
		t.Fatalf("expected verbatim error, got %s", w2.Body.String())
	}
}

func TestSetMonitorTags_Diff(t *testing.T) {
	app, r := setupTest(t)
	sid := createTestSession(t, app)
	inst, _ := app.database.CreateKumaInstance(&db.KumaInstance{Name: "k1", URL: "http://kuma:3001", Username: "u", Password: "p", Enabled: true})
	restoreVerify := kuma.SetVerifySocketIOLoginTestHook(func(url, user, pass string) error { return nil })
	defer restoreVerify()
	restoreQ := kuma.SetQueryMonitorsTestHook(func(url, user, pass string) ([]kuma.KumaMonitor, error) {
		return []kuma.KumaMonitor{{ID: 10, Name: "m", Tags: []kuma.MonitorTag{{ID: 1}, {ID: 2}}}}, nil
	})
	defer restoreQ()
	var added, deleted []int
	restoreAdd := kuma.SetAddMonitorTagTestHook(func(url, user, pass string, monitorID, tagID int) error {
		added = append(added, tagID)
		return nil
	})
	defer restoreAdd()
	restoreDel := kuma.SetDeleteMonitorTagTestHook(func(url, user, pass string, monitorID, tagID int) error {
		deleted = append(deleted, tagID)
		return nil
	})
	defer restoreDel()

	// Desired tags [1,2] with current [1,2] => no-ops
	body := `{"tags":[1,2]}`
	req := authRequest(t, "PUT", fmt.Sprintf("/api/monitors/10/tags?instance=%d", inst.ID), body, sid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(added) != 0 || len(deleted) != 0 {
		t.Fatalf("expected no ops, got added=%v deleted=%v", added, deleted)
	}

	// Desired tags with object form [{"id":1},{"id":3}] => add 3, remove 2
	added, deleted = nil, nil
	body2 := `{"tags":[{"id":1,"name":"x"},{"id":3,"name":"y"}]}`
	req2 := authRequest(t, "PUT", fmt.Sprintf("/api/monitors/10/tags?instance=%d", inst.ID), body2, sid)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w2.Body).Decode(&resp)

	// Desired empty diff? Also test raw array form [1,2]
	added, deleted = nil, nil
	body3 := `[1,2]`
	req3 := authRequest(t, "PUT", fmt.Sprintf("/api/monitors/10/tags?instance=%d", inst.ID), body3, sid)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 raw array, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestSetMonitorTags_InvalidPayload(t *testing.T) {
	app, r := setupTest(t)
	sid := createTestSession(t, app)
	inst, _ := app.database.CreateKumaInstance(&db.KumaInstance{Name: "k1", URL: "http://kuma:3001", Username: "u", Password: "p", Enabled: true})
	restoreVerify := kuma.SetVerifySocketIOLoginTestHook(func(url, user, pass string) error { return nil })
	defer restoreVerify()
	body := `{"tags":"not-an-array"}`
	req := authRequest(t, "PUT", fmt.Sprintf("/api/monitors/1/tags?instance=%d", inst.ID), body, sid)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid tags, got %d: %s", w.Code, w.Body.String())
	}
}
