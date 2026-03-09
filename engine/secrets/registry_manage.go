package secrets

import (
	"fmt"
	"sort"
	"strings"
)

// NormalizeRef canonicalizes secret reference names.
func NormalizeRef(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// SetDefinition creates or updates a secret reference.
func (r *Registry) SetDefinition(name, envVar, description string, roles []string) error {
	if r == nil {
		return fmt.Errorf("secret registry is nil")
	}
	if r.Secrets == nil {
		r.Secrets = map[string]Definition{}
	}
	ref := NormalizeRef(name)
	if ref == "" {
		return fmt.Errorf("secret name is required")
	}
	env := strings.ToUpper(strings.TrimSpace(envVar))
	if env == "" {
		return fmt.Errorf("env var is required")
	}
	normalizedRoles, invalidRoles := normalizeAndValidateRoles(roles)
	if len(invalidRoles) > 0 {
		return fmt.Errorf("unsupported secret roles: %s", strings.Join(invalidRoles, ", "))
	}
	r.Secrets[ref] = Definition{
		Env:         env,
		Description: strings.TrimSpace(description),
		Roles:       normalizedRoles,
	}
	return nil
}

// DeleteDefinition removes a secret reference.
func (r *Registry) DeleteDefinition(name string) bool {
	if r == nil || r.Secrets == nil {
		return false
	}
	ref := NormalizeRef(name)
	if ref == "" {
		return false
	}
	if _, ok := r.Secrets[ref]; !ok {
		return false
	}
	delete(r.Secrets, ref)
	return true
}

// ListRefs returns secret ref names in deterministic order.
func (r *Registry) ListRefs() []string {
	if r == nil || len(r.Secrets) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.Secrets))
	for ref := range r.Secrets {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}
