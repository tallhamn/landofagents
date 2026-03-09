package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadRegistry loads config/secrets.yml. Missing file returns an empty registry.
func LoadRegistry(kitDir string) (*Registry, error) {
	path := RegistryPath(kitDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Registry{Secrets: map[string]Definition{}}, nil
		}
		return nil, fmt.Errorf("read secret registry: %w", err)
	}
	var reg Registry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parse secret registry: %w", err)
	}
	if reg.Secrets == nil {
		reg.Secrets = map[string]Definition{}
	}

	normalized := make(map[string]Definition, len(reg.Secrets))
	for rawRef, def := range reg.Secrets {
		ref := NormalizeRef(rawRef)
		if ref == "" {
			continue
		}
		if _, exists := normalized[ref]; exists {
			return nil, fmt.Errorf("duplicate secret ref after normalization: %s", ref)
		}
		roles, invalid := normalizeAndValidateRoles(def.Roles)
		if len(invalid) > 0 {
			return nil, fmt.Errorf("secret %q has unsupported roles: %s", ref, strings.Join(invalid, ", "))
		}
		env := strings.ToUpper(strings.TrimSpace(def.Env))
		if env == "" {
			return nil, fmt.Errorf("secret %q has empty env var", ref)
		}
		normalized[ref] = Definition{
			Env:         env,
			Description: strings.TrimSpace(def.Description),
			Roles:       roles,
		}
	}
	reg.Secrets = normalized
	return &reg, nil
}

// Save writes the registry to config/secrets.yml.
func (r *Registry) Save(kitDir string) error {
	if r == nil {
		return fmt.Errorf("secret registry is nil")
	}
	if r.Secrets == nil {
		r.Secrets = map[string]Definition{}
	}
	data, err := yaml.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal secret registry: %w", err)
	}
	path := RegistryPath(kitDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
