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
	configDir := filepath.Join(input.WorkspaceDir, ".codex")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return PrepareOutput{}, fmt.Errorf("create codex config dir: %w", err)
	}

	// Seed auth.json from host if available
	hostAuth := filepath.Join(os.Getenv("HOME"), ".codex", "auth.json")
	destAuth := filepath.Join(configDir, "auth.json")
	if _, err := os.Stat(destAuth); os.IsNotExist(err) {
		if data, err := os.ReadFile(hostAuth); err == nil {
			os.WriteFile(destAuth, data, 0600)
		}
	}

	return PrepareOutput{
		RuntimeEnv:   input.RuntimeEnv,
		AgentVolumes: []string{configDir + ":" + codexConfigMountTarget},
	}, nil
}
