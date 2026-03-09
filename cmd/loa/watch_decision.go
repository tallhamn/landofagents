package main

import (
	"fmt"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func extractCommandContext(r audit.Record) string {
	if r.Context == nil {
		return ""
	}
	raw, ok := r.Context["command"]
	if !ok {
		return ""
	}
	cmd := strings.TrimSpace(fmt.Sprintf("%v", raw))
	if cmd == "" {
		return ""
	}
	if len(cmd) > 100 {
		return cmd[:97] + "..."
	}
	return cmd
}

func decisionPathLabel(path, decision string) string {
	decision = strings.ToLower(strings.TrimSpace(decision))
	switch path {
	case "policy":
		if decision == "deny" {
			return "blocked by policy"
		}
		return "allowed by policy"
	case "log", "observe":
		return "log mode"
	case "approve_wait":
		return "granted during ask wait"
	case "one_time_allow":
		return "allowed once by operator"
	case "one_time_deny":
		return "blocked once by operator"
	case "shell_observe", "activity_exec":
		return "activity observed"
	case "activity_file":
		return "file activity observed"
	case "unmapped":
		return "unmapped command"
	case "pipe_to_shell":
		return "blocked pipe-to-shell"
	case "lifecycle":
		return "policy lifecycle"
	case "error":
		return "error"
	default:
		if strings.TrimSpace(path) == "" {
			return "unspecified"
		}
		return path
	}
}

func fileActivityLine(r audit.Record) string {
	if strings.TrimSpace(r.DecisionPath) != "activity_file" {
		return ""
	}
	files := contextStringSlice(r.Context, "files")
	total := contextInt(r.Context, "total_files")
	if total <= 0 {
		total = len(files)
	}
	if total <= 0 {
		return ""
	}
	display := files
	if len(display) > 3 {
		display = display[:3]
	}
	out := strings.Join(display, ", ")
	remaining := total - len(display)
	if remaining > 0 {
		if out != "" {
			out += ", "
		}
		out += fmt.Sprintf("+%d more", remaining)
	}
	return out
}

func watchDecisionLabel(r audit.Record) string {
	decision := strings.ToLower(strings.TrimSpace(r.Decision))
	path := strings.ToLower(strings.TrimSpace(r.DecisionPath))
	if decision == "deny" && path == "policy" && isNoPolicyDenialReason(r.DenialReason) {
		return "blocked since no policy exists"
	}
	return decisionPathLabel(r.DecisionPath, decision)
}

func isNoPolicyDenialReason(reason string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(reason)), "no policy permits ")
}
