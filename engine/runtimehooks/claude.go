package runtimehooks

import (
	"fmt"
	"os"
	"path/filepath"
)

func init() {
	Register("claude-code", func() Hook { return claudeCodeHook{} })
	RegisterBillingPath("claude-code", claudeBillingPathForMode)
}

const claudeConfigMountTarget = "/home/node/.claude"

type claudeCodeHook struct{}

func (claudeCodeHook) ManagedMountTargets() []string {
	return []string{claudeConfigMountTarget}
}

func (claudeCodeHook) Prepare(input PrepareInput) (PrepareOutput, error) {
	configDir := filepath.Join(input.WorkspaceDir, ".claude")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return PrepareOutput{}, fmt.Errorf("create claude config dir: %w", err)
	}

	authMode := resolveClaudeAuthMode()
	runtimeEnv := filterClaudeRuntimeEnvVars(input.RuntimeEnv, authMode)

	if authMode == "oauth" && os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") == "" {
		if err := seedClaudeAuth(configDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not seed Claude auth from host: %v\n", err)
			fmt.Fprintf(os.Stderr, "  Continue without pre-seeded auth. Set CLAUDE_CODE_OAUTH_TOKEN, or run 'claude auth login' in the container.\n")
		}
	}
	seedClaudeConfig(configDir)
	commandPolicyMode := resolveCommandPolicyMode()

	return PrepareOutput{
		AuthMode:   authMode,
		RuntimeEnv: runtimeEnv,
		AgentEnv: []string{
			"CLAUDE_CONFIG_DIR=" + claudeConfigMountTarget,
			"LOA_COMMAND_POLICY_MODE=" + commandPolicyMode,
		},
		AgentVolumes: []string{fmt.Sprintf("%s:%s", configDir, claudeConfigMountTarget)},
	}, nil
}
