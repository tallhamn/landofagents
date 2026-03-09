package runtimehooks

import (
	"os"
	"path/filepath"
	"strings"
)

// seedClaudeConfig writes a minimal .claude.json to the agent's config directory
// so Claude Code doesn't prompt for initial setup inside the container.
func seedClaudeConfig(configDir string) {
	configPath := filepath.Join(configDir, ".claude.json")

	// Already exists — skip
	if _, err := os.Stat(configPath); err == nil {
		return
	}

	for _, hostPath := range hostClaudeConfigPaths() {
		data, err := os.ReadFile(hostPath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == "" {
			continue
		}
		if err := os.WriteFile(configPath, data, 0600); err == nil {
			return
		}
	}

	_ = os.WriteFile(configPath, []byte(`{"bypassPermissionsModeAccepted":true}`), 0600)
}

func hostClaudeConfigPaths() []string {
	var paths []string
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		paths = append(paths, filepath.Join(dir, ".claude.json"))
	}

	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".claude", ".claude.json"),
			filepath.Join(home, ".claude.json"),
		)
	}

	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
