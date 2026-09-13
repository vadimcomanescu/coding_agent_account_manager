package refresh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Dicklesworthstone/coding_agent_account_manager/internal/authfile"
)

// quarantineFile records the fingerprint of a Codex refresh token that the
// provider rejected as already consumed. It lives beside the vault snapshot it
// describes.
const quarantineFile = ".refresh-quarantine"

// codexVaultAuthPath is the vault snapshot a Codex refresh reads its token from.
func codexVaultAuthPath(vault *authfile.Vault, profile string) string {
	return filepath.Join(vault.ProfilePath("codex", profile), "auth.json")
}

// codexReconcileCandidates lists the on-disk copies of a Codex credential that
// may be fresher than the vault snapshot: the live auth file for the current
// HOME, and the isolated profile's codex_home copy, which sits beside the vault
// under the same caam data directory.
func codexReconcileCandidates(vault *authfile.Vault, profile string) []string {
	var candidates []string

	if fileSet, ok := authfile.GetAuthFileSet("codex"); ok {
		for _, spec := range fileSet.Files {
			if filepath.Base(spec.Path) == "auth.json" {
				candidates = append(candidates, spec.Path)
			}
		}
	}

	candidates = append(candidates, filepath.Join(
		filepath.Dir(vault.BasePath()), "profiles", "codex", profile, "codex_home", "auth.json"))

	return candidates
}

// ReconcileCodexVault adopts a fresher live Codex credential into the vault.
//
// OpenAI rotates Codex refresh tokens on every use: the Codex CLI refreshes the
// file it runs against and the previous refresh_token is consumed. A vault
// snapshot taken before that rotation therefore holds a dead token, and every
// later refresh from it returns refresh_token_reused while a working token sits
// in the live file. Sync between the vault and the live copy ran one way only,
// so nothing ever repaired that. This pulls the newest copy back.
//
// Reports whether the vault snapshot was replaced. Conservative by
// construction: a candidate is adopted only when authfile.CodexLiveIsNewer
// confirms it carries the same OpenAI identity and a strictly newer refresh
// timestamp, so a different account, an unreadable file, or an unparseable
// timestamp leaves the vault alone.
func ReconcileCodexVault(vault *authfile.Vault, profile string) (bool, error) {
	if vault == nil || profile == "" {
		return false, nil
	}

	vaultAuth := codexVaultAuthPath(vault, profile)
	if _, err := os.Stat(vaultAuth); err != nil {
		return false, nil // nothing vaulted for this profile; nothing to reconcile
	}

	// Walk the candidates keeping the freshest one: each is compared against the
	// best copy found so far, starting from the vault snapshot itself.
	newest := ""
	reference := vaultAuth
	for _, candidate := range codexReconcileCandidates(vault, profile) {
		if candidate == "" || candidate == vaultAuth || candidate == newest {
			continue
		}
		if authfile.CodexLiveIsNewer(candidate, reference) {
			newest = candidate
			reference = candidate
		}
	}

	if newest == "" {
		return false, nil
	}

	data, err := os.ReadFile(newest)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", newest, err)
	}

	tmpPath := vaultAuth + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return false, fmt.Errorf("write vault auth: %w", err)
	}
	if err := os.Rename(tmpPath, vaultAuth); err != nil {
		os.Remove(tmpPath)
		return false, fmt.Errorf("replace vault auth: %w", err)
	}

	// A token adopted from elsewhere is live again; drop any quarantine the
	// dead one left behind.
	clearQuarantine(vault, profile)

	return true, nil
}

// tokenFingerprint is a non-reversible short identifier for a refresh token, so
// a quarantine record can name the token it refers to without storing it.
func tokenFingerprint(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

// quarantinePath is where a profile's quarantine record lives.
func quarantinePath(vault *authfile.Vault, profile string) string {
	return filepath.Join(vault.ProfilePath("codex", profile), quarantineFile)
}

// markQuarantine records that the provider rejected this refresh token as
// already consumed, so later runs do not present it again. Replaying a consumed
// token is what OpenAI's reuse detection punishes, and it can revoke the whole
// token family, including the session that still works.
func markQuarantine(vault *authfile.Vault, profile, token string) {
	fp := tokenFingerprint(token)
	if fp == "" {
		return
	}
	_ = os.WriteFile(quarantinePath(vault, profile), []byte(fp+"\n"), 0600)
}

// clearQuarantine removes a profile's quarantine record.
func clearQuarantine(vault *authfile.Vault, profile string) {
	_ = os.Remove(quarantinePath(vault, profile))
}

// isQuarantined reports whether the vault's current refresh token is the one a
// previous run saw rejected as consumed. A different token clears the record:
// the profile was re-authenticated or reconciled, and is worth trying again.
func isQuarantined(vault *authfile.Vault, profile, token string) bool {
	fp := tokenFingerprint(token)
	if fp == "" {
		return false
	}
	data, err := os.ReadFile(quarantinePath(vault, profile))
	if err != nil {
		return false
	}
	if strings.TrimSpace(string(data)) != fp {
		clearQuarantine(vault, profile)
		return false
	}
	return true
}
