package runtimehooks

import (
	"os"
	"sort"
	"strings"
)

func filterClaudeRuntimeEnvVars(envVars []string, mode string) []string {
	allowed := map[string]bool{}
	switch mode {
	case "api":
		allowed["ANTHROPIC_API_KEY"] = true
	case "bedrock":
		for _, env := range []string{
			"AWS_ACCESS_KEY_ID",
			"AWS_SECRET_ACCESS_KEY",
			"AWS_SESSION_TOKEN",
			"AWS_REGION",
			"AWS_DEFAULT_REGION",
			"AWS_PROFILE",
		} {
			allowed[env] = true
		}
	case "vertex":
		for _, env := range []string{
			"GOOGLE_APPLICATION_CREDENTIALS",
			"GOOGLE_CLOUD_PROJECT",
			"GOOGLE_CLOUD_LOCATION",
			"VERTEX_REGION",
		} {
			allowed[env] = true
		}
	case "foundry":
		for _, env := range []string{
			"AZURE_OPENAI_API_KEY",
			"AZURE_OPENAI_ENDPOINT",
			"AZURE_API_VERSION",
		} {
			allowed[env] = true
		}
	default: // oauth
		allowed["CLAUDE_CODE_OAUTH_TOKEN"] = true
	}

	var filtered []string
	for _, envVar := range envVars {
		if allowed[envVar] {
			filtered = append(filtered, envVar)
		}
	}
	return filtered
}

// ClaudeExposure summarizes effective auth/env behavior for Claude runtime.
type ClaudeExposure struct {
	RequestedAuthMode string
	EffectiveAuthMode string
	CommandPolicyMode string
	BillingPath       string
	OAuthAvailable    bool
	DeclaredEnv       []string
	ForwardedEnv      []string
	PresentEnv        []string
	MissingEnv        []string
}

// SummarizeClaudeExposure returns effective auth/env exposure for the current host environment.
// It does not mutate workspace state and is safe for diagnostics output.
func SummarizeClaudeExposure(runtimeEnv []string) ClaudeExposure {
	requested := strings.ToLower(strings.TrimSpace(os.Getenv("LOA_CLAUDE_AUTH_MODE")))
	if requested == "" {
		requested = "auto"
	}
	effective := resolveClaudeAuthMode()
	forwarded := filterClaudeRuntimeEnvVars(runtimeEnv, effective)
	present, missing := splitEnvPresence(forwarded)

	return ClaudeExposure{
		RequestedAuthMode: requested,
		EffectiveAuthMode: effective,
		CommandPolicyMode: resolveCommandPolicyMode(),
		BillingPath:       claudeBillingPathForMode(effective),
		OAuthAvailable:    hasHostClaudeOAuth(),
		DeclaredEnv:       sortedCopy(runtimeEnv),
		ForwardedEnv:      sortedCopy(forwarded),
		PresentEnv:        present,
		MissingEnv:        missing,
	}
}

func splitEnvPresence(names []string) (present, missing []string) {
	for _, n := range names {
		if strings.TrimSpace(os.Getenv(n)) != "" {
			present = append(present, n)
		} else {
			missing = append(missing, n)
		}
	}
	sort.Strings(present)
	sort.Strings(missing)
	return present, missing
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}
