package auth

// OIDC login via Authelia (Authorization Code + PKCE S256).
// NOTE: This synapse is the Authelia sync tool, not Matrix Synapse —
// native Matrix OIDC/SSO is out of scope.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"synapse/internal/db"
)

// Config holds OIDC client settings from OIDC_* env vars.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// readSecret returns OIDC_CLIENT_SECRET, supporting OIDC_CLIENT_SECRET_FILE
// (docker secret) which takes precedence when set.
func readSecret() string {
	if f := os.Getenv("OIDC_CLIENT_SECRET_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return os.Getenv("OIDC_CLIENT_SECRET")
}

// LoadFromEnv reads OIDC_* env vars. Defaults target Authelia at
// https://authelia.vandijke.xyz with scopes "openid email profile groups".
func LoadFromEnv() Config {
	scopes := strings.Fields(strings.ReplaceAll(getEnv("OIDC_SCOPES", "openid email profile groups"), ",", " "))
	return Config{
		Issuer:       getEnv("OIDC_ISSUER", "https://authelia.vandijke.xyz"),
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: readSecret(),
		RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
		Scopes:       scopes,
	}
}

// Enabled reports whether OIDC login is configured. Empty ClientID means
// OIDC is off and local session+token auth behavior is unchanged.
func (c Config) Enabled() bool {
	return c.ClientID != "" && c.Issuer != ""
}

// Claims is the subset of ID token claims synapse cares about.
type Claims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
}

// Validate enforces email_verified=true and a non-empty email.
func (cl Claims) Validate() error {
	if cl.Email == "" {
		return errors.New("missing email claim")
	}
	if !cl.EmailVerified {
		return errors.New("email not verified")
	}
	return nil
}

// GenerateVerifier returns a PKCE code_verifier (43-128 chars, unreserved).
func GenerateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ChallengeS256 derives the PKCE S256 code_challenge for a verifier.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateStateNonce returns a hex random string for state/nonce cookies.
func GenerateStateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LinkOrProvision looks up a local user by verified email and creates one on
// first login. OIDC users get an unusable password marker ("oidc:<sub>") so
// they can only authenticate via OIDC, never via local password login.
// ponytail: subject/groups live in the session, not new DB columns; add
// admin_users.oidc_subject/groups columns if admin gating needs persistence.
func LinkOrProvision(database *db.DB, email, subject string) (int64, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return 0, errors.New("email is required")
	}
	if u, err := database.GetAdminUser(email); err == nil && u != nil {
		return u.ID, nil
	}
	return database.CreateAdminUser(email, "oidc:"+subject)
}
