package authfile

import (
	"encoding/json"
	"os"
	"strings"
)

// ClaudeLoginLabel names the account a .claude.json at path says is logged
// in: its email, else its account uuid, else a legacy account string. It is a
// display label only and proves nothing about who owns the credentials.
func ClaudeLoginLabel(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return ""
	}
	keys := claudeIdentityKeys(root)
	for _, prefix := range []string{"email:", "uuid:", "account:"} {
		for _, key := range keys {
			if strings.HasPrefix(key, prefix) {
				return strings.TrimPrefix(key, prefix)
			}
		}
	}
	return ""
}
