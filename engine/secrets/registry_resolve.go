package secrets

import (
	"sort"
	"strings"
)

// ResolveAllowedEnvFromRefs resolves env vars for granted secret refs.
func (r *Registry) ResolveAllowedEnvFromRefs(refs []string) (envVars []string, missingRefs []string) {
	if len(refs) == 0 {
		return nil, nil
	}
	seenEnv := map[string]bool{}
	seenMissing := map[string]bool{}
	for _, raw := range refs {
		ref := NormalizeRef(raw)
		if ref == "" {
			continue
		}
		def, ok := r.Secrets[ref]
		if !ok {
			if !seenMissing[ref] {
				missingRefs = append(missingRefs, ref)
				seenMissing[ref] = true
			}
			continue
		}
		env := strings.ToUpper(strings.TrimSpace(def.Env))
		if env == "" || seenEnv[env] {
			continue
		}
		seenEnv[env] = true
		envVars = append(envVars, env)
	}
	sort.Strings(envVars)
	sort.Strings(missingRefs)
	return envVars, missingRefs
}
