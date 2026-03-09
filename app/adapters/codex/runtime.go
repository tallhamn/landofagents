// Package codex provides runtime detection helpers for the Codex runtime,
// keeping runtime-specific logic out of the engine and CLI layers.
package codex

import "strings"

const RuntimeName = "codex"

func IsRuntime(runtimeName string) bool {
	return strings.EqualFold(strings.TrimSpace(runtimeName), RuntimeName)
}

func InlineUnsupportedReason(runtimeName string) (string, bool) {
	if IsRuntime(runtimeName) {
		return "", false
	}
	return "", false
}
