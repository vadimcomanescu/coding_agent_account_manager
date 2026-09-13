package refresh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
)

// codexJWT builds an unsigned JWT carrying an email identity claim and an
// issued-at, which is all the identity and freshness parsing reads.
func codexJWT(t *testing.T, email string, iat time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	raw, err := json.Marshal(map[string]interface{}{
		"email": email,
		"sub":   "user-" + email,
		"iat":   iat.Unix(),
	})
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

// writeCodexAuth writes a Codex-style auth.json for one account, stamped with a
// refresh time and carrying a named refresh token.
func writeCodexAuth(t *testing.T, path, email, refreshToken string, refreshedAt time.Time) {
	t.Helper()
	auth := map[string]interface{}{
		"last_refresh": refreshedAt.Format(time.RFC3339),
		"tokens": map[string]interface{}{
			"id_token":      codexJWT(t, email, refreshedAt),
			"access_token":  codexJWT(t, email, refreshedAt),
			"refresh_token": refreshToken,
		},
	}
	raw, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal codex auth: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatalf("write auth: %v", err)
	}
}

// vaultRefreshToken reads back the refresh token a vault profile holds.
func vaultRefreshToken(t *testing.T, vault *authfile.Vault, profile string) string {
	t.Helper()
	token, err := getRefreshTokenFromJSON(codexVaultAuthPath(vault, profile))
	if err != nil {
		t.Fatalf("read vault refresh token: %v", err)
	}
	return token
}

// codexTestVault sets up a vault profile and an isolated CODEX_HOME, and
// returns the vault plus the live auth path.
func codexTestVault(t *testing.T, profile string) (*authfile.Vault, string) {
	t.Helper()
	root := t.TempDir()
	codexHome := filepath.Join(root, "codex-home")
	if err := os.MkdirAll(codexHome, 0700); err != nil {
		t.Fatalf("mkdir codex home: %v", err)
	}
	t.Setenv("CODEX_HOME", codexHome)

	vault := authfile.NewVault(filepath.Join(root, "caam", "vault"))
	if err := os.MkdirAll(vault.ProfilePath("codex", profile), 0700); err != nil {
		t.Fatalf("mkdir vault profile: %v", err)
	}
	return vault, filepath.Join(codexHome, "auth.json")
}

func TestReconcileCodexVault_AdoptsNewerLive(t *testing.T) {
	vault, livePath := codexTestVault(t, "main")
	now := time.Now().UTC()

	writeCodexAuth(t, codexVaultAuthPath(vault, "main"), "user@example.com", "spent-token", now.Add(-48*time.Hour))
	writeCodexAuth(t, livePath, "user@example.com", "live-token", now.Add(-1*time.Hour))

	adopted, err := ReconcileCodexVault(vault, "main")
	if err != nil {
		t.Fatalf("ReconcileCodexVault: %v", err)
	}
	if !adopted {
		t.Fatal("newer live credential was not adopted into the vault")
	}
	if got := vaultRefreshToken(t, vault, "main"); got != "live-token" {
		t.Errorf("vault refresh token = %q, want the live one", got)
	}
}

func TestReconcileCodexVault_IgnoresADifferentAccount(t *testing.T) {
	vault, livePath := codexTestVault(t, "main")
	now := time.Now().UTC()

	writeCodexAuth(t, codexVaultAuthPath(vault, "main"), "user@example.com", "vault-token", now.Add(-48*time.Hour))
	writeCodexAuth(t, livePath, "someone-else@example.com", "other-token", now)

	adopted, err := ReconcileCodexVault(vault, "main")
	if err != nil {
		t.Fatalf("ReconcileCodexVault: %v", err)
	}
	if adopted {
		t.Fatal("a different account was adopted into the vault")
	}
	if got := vaultRefreshToken(t, vault, "main"); got != "vault-token" {
		t.Errorf("vault refresh token = %q, want it untouched", got)
	}
}

func TestReconcileCodexVault_AdoptsNewerIsolatedProfile(t *testing.T) {
	vault, _ := codexTestVault(t, "work")
	now := time.Now().UTC()

	writeCodexAuth(t, codexVaultAuthPath(vault, "work"), "user@example.com", "spent-token", now.Add(-48*time.Hour))
	isolated := filepath.Join(filepath.Dir(vault.BasePath()), "profiles", "codex", "work", "codex_home", "auth.json")
	writeCodexAuth(t, isolated, "user@example.com", "isolated-token", now.Add(-2*time.Hour))

	adopted, err := ReconcileCodexVault(vault, "work")
	if err != nil {
		t.Fatalf("ReconcileCodexVault: %v", err)
	}
	if !adopted {
		t.Fatal("newer isolated-profile credential was not adopted into the vault")
	}
	if got := vaultRefreshToken(t, vault, "work"); got != "isolated-token" {
		t.Errorf("vault refresh token = %q, want the isolated one", got)
	}
}

func TestRefreshProfile_CodexRefreshesTheTokenTheCLIRotatedTo(t *testing.T) {
	vault, livePath := codexTestVault(t, "main")
	now := time.Now().UTC()

	// The vault snapshot predates a rotation the Codex CLI performed, so its
	// refresh token is already consumed and only the live one still works.
	writeCodexAuth(t, codexVaultAuthPath(vault, "main"), "user@example.com", "spent-token", now.Add(-48*time.Hour))
	writeCodexAuth(t, livePath, "user@example.com", "live-token", now.Add(-1*time.Hour))

	original := RefreshCodexToken
	defer func() { RefreshCodexToken = original }()
	RefreshCodexToken = func(ctx context.Context, refreshToken string) (*TokenResponse, error) {
		if refreshToken == "spent-token" {
			return nil, ErrRefreshTokenReused
		}
		return &TokenResponse{AccessToken: "minted-access", RefreshToken: "minted-refresh", ExpiresIn: 3600}, nil
	}

	if err := RefreshProfile(context.Background(), "codex", "main", vault, nil); err != nil {
		t.Fatalf("RefreshProfile: %v", err)
	}
	if got := vaultRefreshToken(t, vault, "main"); got != "minted-refresh" {
		t.Errorf("vault refresh token = %q, want the newly minted one", got)
	}
}

func TestRefreshProfile_CodexDoesNotReplayAConsumedToken(t *testing.T) {
	vault, livePath := codexTestVault(t, "main")
	now := time.Now().UTC()

	// Vault and live hold the same credential, so there is nothing fresher to
	// adopt: the account genuinely needs an interactive login.
	writeCodexAuth(t, codexVaultAuthPath(vault, "main"), "user@example.com", "spent-token", now.Add(-1*time.Hour))
	writeCodexAuth(t, livePath, "user@example.com", "spent-token", now.Add(-1*time.Hour))

	original := RefreshCodexToken
	defer func() { RefreshCodexToken = original }()
	calls := 0
	RefreshCodexToken = func(ctx context.Context, refreshToken string) (*TokenResponse, error) {
		calls++
		return nil, ErrRefreshTokenReused
	}

	err := RefreshProfile(context.Background(), "codex", "main", vault, nil)
	if !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("first refresh error = %v, want a reuse error", err)
	}

	err = RefreshProfile(context.Background(), "codex", "main", vault, nil)
	if !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("second refresh error = %v, want a reuse error", err)
	}
	if calls != 1 {
		t.Errorf("token endpoint called %d times, want 1: a consumed token must not be presented again", calls)
	}
}
