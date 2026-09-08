package auth

import (
	"strings"
	"testing"

	"synapse/internal/db"
)

func TestClaimsValidate(t *testing.T) {
	if err := (Claims{Email: "a@example.com", EmailVerified: true}).Validate(); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}
	if err := (Claims{Email: "", EmailVerified: true}).Validate(); err == nil {
		t.Fatal("missing email accepted")
	}
	if err := (Claims{Email: "a@example.com"}).Validate(); err == nil {
		t.Fatal("unverified email accepted")
	}
}

func TestPKCERoundtrip(t *testing.T) {
	v, err := GenerateVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	if len(v) < 43 || len(v) > 128 {
		t.Fatalf("verifier length %d out of range", len(v))
	}
	c1, c2 := ChallengeS256(v), ChallengeS256(v)
	if c1 == "" || c1 != c2 {
		t.Fatal("challenge not deterministic")
	}
	if c1 == v {
		t.Fatal("challenge must differ from verifier")
	}
}

func TestLinkOrProvision(t *testing.T) {
	database, err := db.Open(t.TempDir() + "/oidc.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	id1, err := LinkOrProvision(database, "User@Example.com", "sub-1")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Same email (case-insensitive) links, no duplicate.
	id2, err := LinkOrProvision(database, "user@example.com", "sub-1")
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("link created duplicate: %d vs %d", id1, id2)
	}
	u, err := database.GetAdminUser("user@example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !strings.HasPrefix(u.Password, "oidc:") {
		t.Fatalf("oidc user must have unusable password marker, got %q", u.Password)
	}
	if _, err := LinkOrProvision(database, "", "sub-x"); err == nil {
		t.Fatal("empty email accepted")
	}
}

func TestLoadFromEnvDefaults(t *testing.T) {
	t.Setenv("OIDC_CLIENT_ID", "")
	cfg := LoadFromEnv()
	if cfg.Enabled() {
		t.Fatal("empty client ID must disable OIDC")
	}
	if cfg.Issuer != "https://authelia.vandijke.xyz" {
		t.Fatalf("default issuer, got %q", cfg.Issuer)
	}
	if len(cfg.Scopes) == 0 || cfg.Scopes[0] != "openid" {
		t.Fatalf("default scopes, got %v", cfg.Scopes)
	}
}
