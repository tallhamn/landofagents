package engine_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/marcusmom/land-of-agents"

// TestEngineNeverImportsAppOrCmd verifies the engine layer only depends
// downward (on gap or stdlib), never on app or cmd.
func TestEngineNeverImportsAppOrCmd(t *testing.T) {
	root := repoRoot(t)
	engineDir := filepath.Join(root, "engine")

	violations := collectViolations(t, engineDir, func(_ string, imp string) string {
		if strings.HasPrefix(imp, modulePath+"/app/") {
			return "engine imports app"
		}
		if strings.HasPrefix(imp, modulePath+"/cmd/") {
			return "engine imports cmd"
		}
		return ""
	})
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("engine layer violations:\n%s", strings.Join(violations, "\n"))
	}
}

// TestGapSpecHasZeroInternalDeps verifies gap types have no
// dependencies within the module.
func TestGapSpecHasZeroInternalDeps(t *testing.T) {
	root := repoRoot(t)
	gapDir := filepath.Join(root, "gap")

	violations := collectViolations(t, gapDir, func(_ string, imp string) string {
		if strings.HasPrefix(imp, modulePath+"/") {
			return "gap imports module package"
		}
		return ""
	})
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("gap isolation violations:\n%s", strings.Join(violations, "\n"))
	}
}

// TestAppNeverImportsCmd verifies the app layer doesn't import cmd.
func TestAppNeverImportsCmd(t *testing.T) {
	root := repoRoot(t)
	appDir := filepath.Join(root, "app")

	violations := collectViolations(t, appDir, func(_ string, imp string) string {
		if strings.HasPrefix(imp, modulePath+"/cmd/") {
			return "app imports cmd"
		}
		return ""
	})
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("app layer violations:\n%s", strings.Join(violations, "\n"))
	}
}

func collectViolations(t *testing.T, rootDir string, classify func(filePath, importPath string) string) []string {
	t.Helper()
	var violations []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if reason := classify(path, p); reason != "" {
				rel, _ := filepath.Rel(rootDir, path)
				violations = append(violations, rel+": "+reason+" -> "+p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", rootDir, err)
	}
	return violations
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// boundary_test.go sits in engine/.
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}
