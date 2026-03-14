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
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return PrepareOutput{}, fmt.Errorf("create codex config dir: %w", err)
	}

	// Seed auth.json from host if available using private permissions.
	hostAuth := filepath.Join(os.Getenv("HOME"), ".codex", "auth.json")
	destAuth := filepath.Join(configDir, "auth.json")
	if _, err := os.Stat(destAuth); os.IsNotExist(err) {
		if data, err := os.ReadFile(hostAuth); err == nil {
			if err := os.WriteFile(destAuth, data, 0600); err != nil {
				return PrepareOutput{}, fmt.Errorf("seed codex auth: %w", err)
			}
		}
	}

	return PrepareOutput{
		RuntimeEnv:   input.RuntimeEnv,
		AgentVolumes: []string{configDir + ":" + codexConfigMountTarget},
	}, nil
}
