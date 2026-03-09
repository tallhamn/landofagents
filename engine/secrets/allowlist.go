package secrets

import (
	"sort"
	"strings"
)

// NormalizeAllowlist canonicalizes env var names for matching.
func NormalizeAllowlist(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		name := strings.ToUpper(strings.TrimSpace(raw))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// FilterDeclaredEnv applies an optional per-agent allowlist to declared runtime env vars.
// If allowlist is empty, all declared vars are forwarded.
func FilterDeclaredEnv(declared, allowlist []string) (forwarded, blocked []string) {
	normalizedAllow := NormalizeAllowlist(allowlist)
	if len(normalizedAllow) == 0 {
		forwarded = append([]string{}, declared...)
		sort.Strings(forwarded)
		return forwarded, nil
	}

	allowedSet := map[string]bool{}
	for _, n := range normalizedAllow {
		allowedSet[n] = true
	}

	for _, raw := range declared {
		name := strings.ToUpper(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if allowedSet[name] {
			forwarded = append(forwarded, name)
		} else {
			blocked = append(blocked, name)
		}
	}
	forwarded = NormalizeAllowlist(forwarded)
	blocked = NormalizeAllowlist(blocked)
	return forwarded, blocked
}

// FilterDeclaredEnvStrict applies declared env filtering, but if explicitPolicy is true
// and the effective allowlist is empty, it fails closed (forwards none).
func FilterDeclaredEnvStrict(declared, allowlist []string, explicitPolicy bool) (forwarded, blocked []string) {
	effective := NormalizeAllowlist(allowlist)
	if explicitPolicy && len(effective) == 0 {
		return nil, NormalizeAllowlist(declared)
	}
	return FilterDeclaredEnv(declared, effective)
}
