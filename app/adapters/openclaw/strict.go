// Package openclaw enforces strict security constraints when LOA is used as
// OpenClaw's worker backend. When enabled, it prevents workers from mounting
// Docker sockets, requires enforce mode for network policies, and validates
// that all workers are launched through the approved gateway.
package openclaw

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	EnvRequireWorkerAPI = "LOA_OPENCLAW_REQUIRE_WORKER_API"
	EnvWorkerBackend    = "WORKER_BACKEND"
	EnvWorkerLauncher   = "OPENCLAW_WORKER_LAUNCHER"
)

const (
	requiredSourceLabelValue = "openclaw-gateway"
	allowedInitialScope      = "existing-active"
	allowedSecretExposure    = "least"
)

var forbiddenSocketSources = map[string]bool{
	"/var/run/docker.sock": true,
	"/run/docker.sock":     true,
}

// IsEnabled reports whether strict OpenClaw worker API mode is enabled.
func IsEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvRequireWorkerAPI)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// IsRuntime reports whether a runtime name maps to OpenClaw.
func IsRuntime(runtimeName string) bool {
	return strings.EqualFold(strings.TrimSpace(runtimeName), "openclaw")
}

// IsStrictForRuntime reports whether strict checks should apply for a runtime.
func IsStrictForRuntime(runtimeName string) bool {
	return IsEnabled() && IsRuntime(runtimeName)
}

// ValidateBackend checks strict backend requirements.
func ValidateBackend() error {
	if !IsEnabled() {
		return nil
	}
	backend := strings.ToLower(strings.TrimSpace(os.Getenv(EnvWorkerBackend)))
	if backend == "loa" {
		return nil
	}
	if backend == "" {
		return fmt.Errorf("openclaw secure mode requires WORKER_BACKEND=loa")
	}
	return fmt.Errorf("openclaw secure mode requires WORKER_BACKEND=loa (got %q)", backend)
}

// ValidateLauncher checks strict launcher requirements.
func ValidateLauncher() error {
	if !IsEnabled() {
		return nil
	}
	launcher := strings.TrimSpace(os.Getenv(EnvWorkerLauncher))
	if launcher == "" {
		return fmt.Errorf("openclaw secure mode requires OPENCLAW_WORKER_LAUNCHER to be set")
	}
	info, err := os.Stat(launcher)
	if err != nil {
		return fmt.Errorf("openclaw secure mode requires OPENCLAW_WORKER_LAUNCHER=%q to exist: %v", launcher, err)
	}
	if info.IsDir() {
		return fmt.Errorf("openclaw secure mode requires OPENCLAW_WORKER_LAUNCHER to be an executable file (got directory %q)", launcher)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("openclaw secure mode requires OPENCLAW_WORKER_LAUNCHER=%q to be executable", launcher)
	}
	return nil
}

// ValidateRunPreflight validates strict OpenClaw runtime requirements before run.
func ValidateRunPreflight(runtimeName string) error {
	if !IsStrictForRuntime(runtimeName) {
		return nil
	}
	if err := ValidateBackend(); err != nil {
		return err
	}
	return ValidateLauncher()
}

// ValidateStrictWorkerLaunch enforces strict launch policy for OpenClaw workers.
func ValidateStrictWorkerLaunch(runtimeName string, requestedMounts []string, mode, initialScope, exposure, sourceLabel string) error {
	if !IsStrictForRuntime(runtimeName) {
		return nil
	}
	if forbidden := ForbiddenVolumeSources(requestedMounts); len(forbidden) > 0 {
		return fmt.Errorf("openclaw secure mode forbids mounting container runtime sockets: %s", strings.Join(forbidden, ", "))
	}
	if strings.ToLower(strings.TrimSpace(mode)) != "enforce" {
		return fmt.Errorf("openclaw secure mode requires network_profile.mode=enforce")
	}
	scope := strings.ToLower(strings.TrimSpace(initialScope))
	if scope != "" && scope != allowedInitialScope {
		return fmt.Errorf("openclaw secure mode requires network_profile.initial_policy_scope=%s (got %q)", allowedInitialScope, scope)
	}
	exposure = strings.ToLower(strings.TrimSpace(exposure))
	if exposure != "" && exposure != allowedSecretExposure {
		return fmt.Errorf("openclaw secure mode requires secrets_profile.exposure=%s (got %q)", allowedSecretExposure, exposure)
	}
	source := strings.ToLower(strings.TrimSpace(sourceLabel))
	if source != requiredSourceLabelValue {
		return fmt.Errorf("openclaw secure mode requires labels.source=%s", requiredSourceLabelValue)
	}
	return nil
}

// ForbiddenVolumeSources returns forbidden host mount sources in deterministic order.
func ForbiddenVolumeSources(volumes []string) []string {
	if len(volumes) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range volumes {
		src := mountSource(v)
		if src == "" {
			continue
		}
		src = filepath.Clean(src)
		if !forbiddenSocketSources[src] || seen[src] {
			continue
		}
		seen[src] = true
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

// LauncherPathOrEmpty returns normalized launcher path for diagnostics.
func LauncherPathOrEmpty() string {
	v := strings.TrimSpace(os.Getenv(EnvWorkerLauncher))
	if v == "" {
		return ""
	}
	return filepath.Clean(v)
}

// StrictValidator implements worker.LaunchValidator for OpenClaw strict mode.
type StrictValidator struct{}

// ValidateWorkerLaunch checks OpenClaw strict-mode launch constraints.
func (StrictValidator) ValidateWorkerLaunch(runtimeName string, requestedMounts []string, mode, initialScope, exposure string, labels map[string]string) error {
	return ValidateStrictWorkerLaunch(runtimeName, requestedMounts, mode, initialScope, exposure, labels["source"])
}

func mountSource(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	parts := strings.Split(spec, ":")
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}
