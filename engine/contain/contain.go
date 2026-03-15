// Package contain orchestrates running an agent in a governed Docker environment.
// It generates a docker-compose setup with three services:
// 1. loa-authz: the LOA ext_authz server (evaluates Cedar policies)
// 2. envoy: forward proxy with ext_authz filter
// 3. agent: the agent container (runtime-specific)
package contain

import "io"

// Options configures a contain run.
type Options struct {
	KitDir    string
	AgentName string
	AgentPort int // ext_authz port (default 9002)
	ProxyPort int // envoy proxy port (default 10000)
	Mode string // "enforce", "log", or "ask" — set by caller from agent config
	ExtraVolumes []string // additional host:container mounts for this run only
	// UseOnlyExtraVolumes narrows user mounts to ExtraVolumes only (ignores agent baseline mounts).
	UseOnlyExtraVolumes bool
	SecretRefs          []string // explicit secret ref override; nil => agent defaults, empty => no secret refs
	SecretRole          string   // secret exposure role context: "gateway" (default) or "worker"
	// CallerEnv holds caller-provided env overrides (key=value). Intersected with
	// agent's allowed_env policy: only vars whose names appear in allowed_env are
	// injected. Caller values override runtime passthrough for the same var name.
	CallerEnv map[string]string
	LogOut    io.Writer
}

// Environment holds the paths produced by SetupEnvironment.
type Environment struct {
	TmpDir      string // root temp directory
	ComposePath string // path to docker-compose.yaml
	KitDir      string // absolute kit directory
	RuntimeEnv  []string
	AuthMode    string // runtime-specific auth mode (when applicable)
}
