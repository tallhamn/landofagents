package runtimehooks

import (
	"fmt"
	"os"
	"strings"
)

func resolveCommandPolicyMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LOA_COMMAND_POLICY_MODE")))
	switch mode {
	case "", "discover":
		return "discover"
	case "off":
		return mode
	default:
		fmt.Fprintf(os.Stderr, "Warning: unsupported LOA_COMMAND_POLICY_MODE=%q, falling back to discover\n", mode)
		return "discover"
	}
}

func resolveClaudeAuthMode() string {
	requested := strings.ToLower(strings.TrimSpace(os.Getenv("LOA_CLAUDE_AUTH_MODE")))
	switch requested {
	case "", "auto":
		return resolveClaudeAutoAuthMode(hasHostClaudeOAuth())
	case "oauth", "api", "bedrock", "vertex", "foundry":
		return requested
	default:
		fmt.Fprintf(os.Stderr, "Warning: unsupported LOA_CLAUDE_AUTH_MODE=%q, falling back to auto\n", requested)
		return resolveClaudeAutoAuthMode(hasHostClaudeOAuth())
	}
}

func resolveClaudeAutoAuthMode(hasOAuth bool) string {
	if hasOAuth {
		return "oauth"
	}
	switch {
	case hasAnyEnv("AWS_ACCESS_KEY_ID", "AWS_PROFILE"):
		return "bedrock"
	case hasAnyEnv("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"):
		return "vertex"
	case hasAnyEnv("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"):
		return "foundry"
	case os.Getenv("ANTHROPIC_API_KEY") != "":
		return "api"
	default:
		return "oauth"
	}
}

func hasAnyEnv(names ...string) bool {
	for _, n := range names {
		if os.Getenv(n) != "" {
			return true
		}
	}
	return false
}

func claudeBillingPathForMode(mode string) string {
	switch mode {
	case "oauth":
		return "Claude subscription (OAuth)"
	case "api":
		return "Anthropic API key"
	case "bedrock":
		return "AWS Bedrock"
	case "vertex":
		return "Google Vertex AI"
	case "foundry":
		return "Microsoft Foundry/Azure"
	default:
		return "unknown"
	}
}
