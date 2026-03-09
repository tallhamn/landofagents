package secrets

import "path/filepath"

// Definition maps a secret reference name to its host env-var source.
type Definition struct {
	Env         string   `yaml:"env"`
	Description string   `yaml:"description,omitempty"`
	Roles       []string `yaml:"roles,omitempty"`
}

// Registry stores all named secret definitions.
type Registry struct {
	Secrets map[string]Definition `yaml:"secrets"`
}

const (
	// RoleGateway indicates a secret may be exposed to a long-lived gateway/runtime process.
	RoleGateway = "gateway"
	// RoleWorker indicates a secret may be exposed to short-lived worker executions.
	RoleWorker = "worker"
)

// RegistryPath returns the secret registry path inside a kit.
func RegistryPath(kitDir string) string {
	return filepath.Join(kitDir, "config", "secrets.yml")
}
