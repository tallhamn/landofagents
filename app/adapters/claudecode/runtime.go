// Package claudecode provides runtime detection and auth/billing helpers
// for the Claude Code runtime, keeping runtime-specific logic out of the
// engine and CLI layers.
package claudecode

import (
	"strings"

	"github.com/marcusmom/land-of-agents/engine/runtimehooks"
)

const RuntimeName = "claude-code"

// Exposure summarizes effective auth/env behavior for Claude runtime.
type Exposure = runtimehooks.ClaudeExposure

func IsRuntime(runtimeName string) bool {
	return strings.EqualFold(strings.TrimSpace(runtimeName), RuntimeName)
}

func InlineUnsupportedReason(runtimeName string) (string, bool) {
	if IsRuntime(runtimeName) {
		return "runtime claude-code", true
	}
	return "", false
}

func SummarizeExposure(runtimeEnv []string) Exposure {
	return runtimehooks.SummarizeClaudeExposure(runtimeEnv)
}

func BillingPath(authMode string) string {
	return runtimehooks.BillingPath(RuntimeName, authMode)
}
