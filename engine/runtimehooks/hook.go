// Package runtimehooks defines the runtime extension boundary for contain.
//
// Responsibilities:
//   - runtime-specific env filtering and defaults
//   - runtime-managed mounts (for state/auth files)
//   - runtime-specific billing/auth mode display labels
//
// Constraints:
//   - contain orchestration stays runtime-agnostic
//   - hooks must return declarative env/mount data, not launch containers
//   - policy enforcement remains in authz/protector, not in hooks
package runtimehooks

// PrepareInput describes the context provided to a runtime setup hook.
type PrepareInput struct {
	WorkspaceDir string   // agent workspace root (e.g. kit/workspaces/<agent>)
	RuntimeEnv   []string // passthrough env var names declared by runtime.yml
}

// PrepareOutput describes runtime-specific container setup results.
type PrepareOutput struct {
	AuthMode     string   // optional display label shown by `loa run`
	RuntimeEnv   []string // filtered/normalized passthrough env var names
	AgentEnv     []string // fixed KEY=VALUE env entries for compose
	AgentVolumes []string // fixed host:container volume mounts for compose
}

// Hook performs runtime-specific setup while keeping contain generic.
type Hook interface {
	ManagedMountTargets() []string
	Prepare(input PrepareInput) (PrepareOutput, error)
}

var (
	hookRegistry        = map[string]func() Hook{}
	billingPathRegistry = map[string]func(authMode string) string{}
)

// Register adds a named hook factory to the registry.
func Register(name string, factory func() Hook) {
	hookRegistry[name] = factory
}

// RegisterBillingPath adds a billing-path renderer for a named runtime.
func RegisterBillingPath(name string, fn func(authMode string) string) {
	billingPathRegistry[name] = fn
}

// ForRuntime returns the hook implementation for the runtime hook name.
func ForRuntime(name string) Hook {
	if factory, ok := hookRegistry[name]; ok {
		return factory()
	}
	return noopHook{}
}

type noopHook struct{}

func (noopHook) ManagedMountTargets() []string { return nil }

func (noopHook) Prepare(input PrepareInput) (PrepareOutput, error) {
	return PrepareOutput{RuntimeEnv: append([]string{}, input.RuntimeEnv...)}, nil
}

// BillingPath returns a human-readable billing/auth path for display.
func BillingPath(hookName, authMode string) string {
	if fn, ok := billingPathRegistry[hookName]; ok {
		return fn(authMode)
	}
	return ""
}
