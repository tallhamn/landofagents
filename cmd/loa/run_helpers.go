package main

import (
	"strings"

	"github.com/marcusmom/land-of-agents/app/adapters/claudecode"
	"github.com/marcusmom/land-of-agents/app/adapters/codex"
	"github.com/marcusmom/land-of-agents/engine/agent"
)

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}

func inlineUnsupportedReason(a agent.Agent) (string, bool) {
	if reason, unsupported := claudecode.InlineUnsupportedReason(a.Runtime); unsupported {
		return reason, true
	}
	if reason, unsupported := codex.InlineUnsupportedReason(a.Runtime); unsupported {
		return reason, true
	}
	return "", false
}

func shellResourceFromCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "_"
	}
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "_"
	}
	i := 0
	for i < len(parts) {
		p := parts[i]
		if strings.Contains(p, "=") && !strings.HasPrefix(p, "=") {
			i++
			continue
		}
		break
	}
	if i >= len(parts) {
		return "_"
	}
	token := parts[i]
	if token == "command" && i+2 < len(parts) && (parts[i+1] == "-v" || parts[i+1] == "--") {
		token = parts[i+2]
	}
	if token == "" {
		return "_"
	}
	if slash := strings.LastIndex(token, "/"); slash >= 0 && slash+1 < len(token) {
		token = token[slash+1:]
	}
	return token
}

func hasFlag(args []string, name string) bool {
	for i, arg := range args {
		if arg == name {
			return true
		}
		if strings.HasPrefix(arg, name+"=") {
			return true
		}
		if arg == "--" {
			return false
		}
		// Handle forms like "--network-scope domain"
		if i > 0 && args[i-1] == name {
			return true
		}
	}
	return false
}
