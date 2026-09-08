package main

// OIDC (Authelia) login tests: status/login disabled behavior, callback
// guards, and the mutation OR rule (OIDC session OR bearer token) when OIDC
// is enabled. Local session+token behavior when disabled is covered by
// TestMutations_RequireSessionAndToken.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"synapse/internal/auth"
	"synapse/internal/db"
	"synapse/internal/kuma"
	"synapse/internal/npm"
)

// setupOIDCTest builds an app+router with OIDC enabled (config-only, no
// provider discovery) so the OR middleware path is exercised without network.
func setupOIDCTest(t *testing.T) (*App, *testRouter) {
	t.Helper()
	tmpDB := t.TempDir() + "/oidc-test.db"
	database, err := db.Open(tmpDB)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	app := &App{
		database:     database,
		kumaRegistry: kuma.NewRegistry(database),
		npmRegistry:  npm.NewRegistry(database),
		oidcCfg:      auth.Config{Issuer: "https://authelia.vandijke.xyz", ClientID: "test-client", Scopes: []string{"openid", "email", "profile", "groups"}},
	}
	r := setupRouter(app)
	return app, &testRouter{r: r}
}

type testRouter struct {
	r http.Handler
}

func (tr *testRouter) serve(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	tr.r.ServeHTTP(w, req)
	return w
}

func createOIDCSession(t *testing.T, app *App, email string) string {
	t.Helper()
	uid, err := auth.LinkOrProvision(app.database, email, "test-sub")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	sid := generateSessionID()
	sessionStoreMu.Lock()
	sessionStore[sid] = sessionInfo{Expiry: time.Now().Add(time.Hour), UserID: uid, OIDC: true, Email: email, Groups: []string{"admins"}}
	sessionStoreMu.Unlock()
	t.Cleanup(func() {
		sessionStoreMu.Lock()
		delete(sessionStore, sid)
		sessionStoreMu.Unlock()
	})
	return sid
}

func createBearerSecret(t *testing.T, app *App, ownerID int64) string {
	t.Helper()
	secret := generateAPIToken()
	if _, err := app.database.CreateAPIToken(ownerID, "oidc-test", hashToken(secret), nil); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return secret
}

func TestOIDCStatus_Disabled(t *testing.T) {
	_, r := setupTest(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/auth/oidc/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["enabled"] != false {
		t.Fatalf("expected enabled=false, got %v", body)
	}
}

func TestOIDCLogin_Disabled404(t *testing.T) {
	_, r := setupTest(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/auth/oidc/login", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestOIDCCallback_BadState(t *testing.T) {
	_, r := setupTest(t)
	req := httptest.NewRequest("GET", "/api/auth/oidc/callback?code=x&state=y", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound && w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 404 (disabled) or 401, got %d", w.Code)
	}
}

func TestOIDCMutations_ORLogic(t *testing.T) {
	app, tr := setupOIDCTest(t)
	body := `{"compose_path":"/tmp/oidc-or-test"}`
	localSID, localUID := createTestSessionRaw(t, app)
	oidcSID := createOIDCSession(t, app, "oidc-user@example.com")
	bearer := createBearerSecret(t, app, localUID)

	// 1. Anonymous → 401, no write.
	w := tr.serve(httptest.NewRequest("POST", "/api/settings", strings.NewReader(body)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// 2. OIDC session alone → 200 (the OR rule).
	req := authRequestNoToken(t, "POST", "/api/settings", body, oidcSID)
	if w := tr.serve(req); w.Code != http.StatusOK {
		t.Fatalf("oidc session: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Bearer alone (no session, automation/NPM bypass) → 200.
	req = authRequestWithToken(t, "POST", "/api/settings", body, "", bearer)
	if w := tr.serve(req); w.Code != http.StatusOK {
		t.Fatalf("bearer only: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Local session alone → 401 missing bearer token (unchanged).
	req = authRequestNoToken(t, "POST", "/api/settings", body, localSID)
	w = tr.serve(req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("local session only: expected 401, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "missing bearer token" {
		t.Fatalf("expected 'missing bearer token', got %q", resp["error"])
	}

	// 5. Invalid bearer, no session → 401.
	req = authRequestWithToken(t, "POST", "/api/settings", body, "", "not-a-real-token")
	if w := tr.serve(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: expected 401, got %d", w.Code)
	}
}

func TestOIDCMutations_ExpiredRevokedRejected(t *testing.T) {
	app, tr := setupOIDCTest(t)
	body := `{"compose_path":"/tmp/oidc-no-write"}`
	_, uid := createTestSessionRaw(t, app)

	past := time.Now().Add(-time.Hour)
	if _, err := app.database.CreateAPIToken(uid, "exp", hashToken("oidc-exp-secret"), &past); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := authRequestWithToken(t, "POST", "/api/settings", body, "", "oidc-exp-secret")
	if w := tr.serve(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired: expected 401, got %d", w.Code)
	}

	id, err := app.database.CreateAPIToken(uid, "rev", hashToken("oidc-rev-secret"), nil)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := app.database.RevokeAPIToken(id); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	req = authRequestWithToken(t, "POST", "/api/settings", body, "", "oidc-rev-secret")
	if w := tr.serve(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked: expected 401, got %d", w.Code)
	}
	if s := app.settings(); s.ComposePath == "/tmp/oidc-no-write" {
		t.Fatal("rejected mutation must not persist")
	}
}

func TestOIDCPublicReads_Anonymous(t *testing.T) {
	_, tr := setupOIDCTest(t)
	for _, p := range []string{"/overview", "/api/public/overview", "/api/auth/oidc/status"} {
		w := tr.serve(httptest.NewRequest("GET", p, nil))
		if w.Code != http.StatusOK && w.Code != http.StatusFound {
			t.Fatalf("GET %s: expected 200/302 anonymous, got %d", p, w.Code)
		}
	}
}
