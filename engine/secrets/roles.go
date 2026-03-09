package secrets

import (
	"sort"
	"strings"
)

// EffectiveRoles returns the normalized role policy for a secret definition.
// If roles are unset, gateway-only exposure is the default.
func EffectiveRoles(def Definition) []string {
	roles, _ := normalizeAndValidateRoles(def.Roles)
	if len(roles) == 0 {
		return []string{RoleGateway}
	}
	return roles
}

// DefinitionAllowsRole reports whether a secret definition can be exposed for a role.
func DefinitionAllowsRole(def Definition, role string) bool {
	role = NormalizeRole(role)
	if role == "" {
		role = RoleGateway
	}
	for _, allowed := range EffectiveRoles(def) {
		if allowed == role {
			return true
		}
	}
	return false
}

// RefsNotExposedToRole returns granted refs that are not exposed to the requested role.
// Undefined refs are ignored here and should be handled separately.
func (r *Registry) RefsNotExposedToRole(refs []string, role string) []string {
	if r == nil || len(refs) == 0 {
		return nil
	}
	role = NormalizeRole(role)
	if role == "" {
		role = RoleGateway
	}
	seen := map[string]bool{}
	var denied []string
	for _, raw := range refs {
		ref := NormalizeRef(raw)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		def, ok := r.Secrets[ref]
		if !ok {
			continue
		}
		if !DefinitionAllowsRole(def, role) {
			denied = append(denied, ref)
		}
	}
	sort.Strings(denied)
	return denied
}

// NormalizeRole canonicalizes a secret exposure role.
func NormalizeRole(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

func normalizeAndValidateRoles(in []string) (roles []string, invalid []string) {
	if len(in) == 0 {
		return nil, nil
	}
	seenRole := map[string]bool{}
	seenInvalid := map[string]bool{}
	for _, raw := range in {
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			role := NormalizeRole(part)
			if role == "" {
				continue
			}
			switch role {
			case RoleGateway, RoleWorker:
				if !seenRole[role] {
					seenRole[role] = true
					roles = append(roles, role)
				}
			default:
				if !seenInvalid[role] {
					seenInvalid[role] = true
					invalid = append(invalid, role)
				}
			}
		}
	}
	sort.Strings(roles)
	sort.Strings(invalid)
	return roles, invalid
}
