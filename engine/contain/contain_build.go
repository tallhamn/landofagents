package contain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
)

func buildLoa(outPath string) error {
	goarch := goruntime.GOARCH
	root := findModuleRoot()
	if root == "." {
		return fmt.Errorf("cannot find LOA source tree from current directory.\n" +
			"Either run from the source directory, or set LOA_SOURCE_DIR:\n" +
			"  export LOA_SOURCE_DIR=/path/to/land-of-agents")
	}
	cmd := exec.Command("go", "build", "-o", outPath, "./cmd/loa")
	cmd.Env = append(os.Environ(),
		"GOOS=linux",
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func findEnvoyConfig() string {
	root := findModuleRoot()
	return filepath.Join(root, "configs", "envoy.yaml.tmpl")
}
