package contain

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/marcusmom/land-of-agents/engine/runtime"
)

// copyRuntimeFiles copies the runtime's build files to the temp dir.
// For build-based runtimes, the Dockerfile is copied as Dockerfile.agent
// and additional files are copied alongside it.
func copyRuntimeFiles(rt *runtime.Runtime, kitDir, tmpDir string) error {
	if rt.Build == nil {
		return nil // image-based runtime, nothing to copy
	}

	runtimeDir := filepath.Join(kitDir, "runtimes", rt.Name)
	src := filepath.Join(runtimeDir, rt.Build.Dockerfile)
	if err := copyFile(src, filepath.Join(tmpDir, "Dockerfile.agent")); err != nil {
		return fmt.Errorf("copy runtime Dockerfile: %w", err)
	}

	for _, f := range rt.Build.Files {
		src := filepath.Join(runtimeDir, f)
		if err := copyFile(src, filepath.Join(tmpDir, f)); err != nil {
			return fmt.Errorf("copy runtime file %s: %w", f, err)
		}
	}

	return nil
}

// writeBaseCedar writes the runtime's base Cedar policies to kitDir/policies/active/.
// This must write to the REAL kit dir (not a temp copy) because the authz
// container bind-mounts kitDir/policies/ at runtime.
func writeBaseCedar(kitDir, agentName, cedar string) error {
	if cedar == "" {
		return nil
	}
	policiesDir := filepath.Join(kitDir, "policies", "active")
	if err := os.MkdirAll(policiesDir, 0755); err != nil {
		return fmt.Errorf("create policies dir: %w", err)
	}
	policyFile := filepath.Join(policiesDir, fmt.Sprintf("_runtime-%s.cedar", agentName))
	if err := os.WriteFile(policyFile, []byte(cedar), 0644); err != nil {
		return fmt.Errorf("write runtime base cedar: %w", err)
	}
	return nil
}
