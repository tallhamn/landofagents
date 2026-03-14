package runtimehooks

import (
	"fmt"
	"os"
	"path/filepath"
)

func init() {
	Register("codex", func() Hook { return codexHook{} })
}

const codexConfigMountTarget = "/home/node/.codex"

type codexHook struct{}

func (codexHook) ManagedMountTargets() []string {
	return []string{codexConfigMountTarget}
}

func (codexHook) Prepare(input PrepareInput) (PrepareOutput, error) {
	// Use 0777 so the container's node user (uid 1000) can write config
	// even when the host process runs as a different uid.
	configDir := filepath.Join(input.WorkspaceDir, ".codex")
	if err := os.MkdirAll(configDir, 0777); err != nil {
		return PrepareOutput{}, fmt.Errorf("create codex config dir: %w", err)
	}

	// Seed auth.json from host if available.
	// Use 0666 so the container's node user can read and refresh tokens.
	hostAuth := filepath.Join(os.Getenv("HOME"), ".codex", "auth.json")
	destAuth := filepath.Join(configDir, "auth.json")
	if _, err := os.Stat(destAuth); os.IsNotExist(err) {
		if data, err := os.ReadFile(hostAuth); err == nil {
			os.WriteFile(destAuth, data, 0666)
		}
	}

	return PrepareOutput{
		RuntimeEnv:   input.RuntimeEnv,
		AgentVolumes: []string{configDir + ":" + codexConfigMountTarget},
	}, nil
}
