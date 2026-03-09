package runtimehooks

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
)

func hasHostClaudeOAuth() bool {
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" {
		return true
	}
	if _, err := os.Stat(hostClaudeCredentialsPath()); err == nil {
		return true
	}
	if goruntime.GOOS == "darwin" {
		_, err := readClaudeCredsFromKeychain()
		return err == nil
	}
	return false
}

// seedClaudeAuth extracts Claude Code credentials from the host and writes them
// into the agent's config directory so the container starts pre-authenticated.
func seedClaudeAuth(configDir string) error {
	credPath := filepath.Join(configDir, ".credentials.json")
	existingCredData, existingErr := os.ReadFile(credPath)
	existingExists := existingErr == nil
	if existingErr != nil && !os.IsNotExist(existingErr) {
		return fmt.Errorf("read existing %s: %w", credPath, existingErr)
	}

	hostCredData, err := readHostClaudeCredentials()
	if err == nil && len(hostCredData) > 0 {
		// Keep file stable when host and workspace credentials already match.
		if existingExists && bytes.Equal(existingCredData, hostCredData) {
			return nil
		}
		return os.WriteFile(credPath, hostCredData, 0600)
	}

	// If host creds aren't currently available, keep existing workspace creds.
	if existingExists {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("host credentials are empty (run 'claude auth login' on host)")
}

func hostClaudeCredentialsPath() string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, ".credentials.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".claude", ".credentials.json")
	}
	return filepath.Join(home, ".claude", ".credentials.json")
}

func readHostClaudeCredentials() ([]byte, error) {
	hostCred := hostClaudeCredentialsPath()
	credData, err := os.ReadFile(hostCred)
	if err == nil {
		if len(credData) == 0 {
			return nil, fmt.Errorf("host credentials at %s are empty", hostCred)
		}
		return credData, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", hostCred, err)
	}

	if goruntime.GOOS == "darwin" {
		credData, err = readClaudeCredsFromKeychain()
		if err != nil {
			return nil, fmt.Errorf("host credentials not found in %s and keychain lookup failed: %w", hostCred, err)
		}
		if len(credData) == 0 {
			return nil, fmt.Errorf("keychain returned empty Claude credentials")
		}
		return credData, nil
	}

	return nil, fmt.Errorf("host credentials not found at %s (run 'claude auth login' on host)", hostCred)
}

func readClaudeCredsFromKeychain() ([]byte, error) {
	var tried []string

	for _, service := range claudeKeychainServiceNames() {
		out, err := exec.Command("security", "find-generic-password", "-s", service, "-w").Output()
		if err == nil {
			data := strings.TrimSpace(string(out))
			if data != "" {
				return []byte(data), nil
			}
		}
		tried = append(tried, service)
	}

	return nil, fmt.Errorf("tried services: %s", strings.Join(tried, ", "))
}

func claudeKeychainServiceNames() []string {
	suffixes := []string{claudeConfigHashSuffix(), ""}
	base := "Claude Code" + claudeOAuthFileSuffix() + "-credentials"

	var names []string
	for _, suffix := range suffixes {
		names = append(names, base+suffix)
	}

	// Fallbacks for users who authenticated before suffix logic changed.
	names = append(names,
		"Claude Code-credentials",
		"Claude Code-staging-oauth-credentials",
		"Claude Code-local-oauth-credentials",
		"Claude Code-custom-oauth-credentials",
	)

	seen := make(map[string]bool, len(names))
	var deduped []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			deduped = append(deduped, n)
		}
	}
	return deduped
}

func claudeOAuthFileSuffix() string {
	if os.Getenv("CLAUDE_CODE_CUSTOM_OAUTH_URL") != "" {
		return "-custom-oauth"
	}
	return ""
}

func claudeConfigHashSuffix() string {
	cfgDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if cfgDir == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(cfgDir))
	hex := fmt.Sprintf("%x", sum[:])
	return "-" + hex[:8]
}
