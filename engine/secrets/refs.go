package secrets

import "sort"

// NormalizeRefs canonicalizes secret refs, dropping empty/duplicate entries.
func NormalizeRefs(refs []string) []string {
	if len(refs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range refs {
		ref := NormalizeRef(raw)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// MissingAllowedRefs returns requested refs that are not present in the allowed set.
func MissingAllowedRefs(requested, allowed []string) []string {
	if len(requested) == 0 {
		return nil
	}
	allowedSet := map[string]bool{}
	for _, raw := range allowed {
		ref := NormalizeRef(raw)
		if ref != "" {
			allowedSet[ref] = true
		}
	}
	var missing []string
	for _, raw := range requested {
		ref := NormalizeRef(raw)
		if ref == "" {
			continue
		}
		if !allowedSet[ref] {
			missing = append(missing, ref)
		}
	}
	return NormalizeRefs(missing)
}

// MissingDefinedRefs returns refs that are not defined in the registry.
func MissingDefinedRefs(reg *Registry, requested []string) []string {
	if reg == nil || len(requested) == 0 {
		return nil
	}
	_, missing := reg.ResolveAllowedEnvFromRefs(requested)
	return NormalizeRefs(missing)
}
