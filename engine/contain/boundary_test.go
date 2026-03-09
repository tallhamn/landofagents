package contain_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const modulePath = "github.com/marcusmom/land-of-agents"

func TestContainCoreDoesNotImportRuntimeAdapters(t *testing.T) {
	root := repoRoot(t)
	containDir := filepath.Join(root, "engine", "contain")

	fset := token.NewFileSet()
	err := filepath.WalkDir(containDir, func(path string, d os.DirEntry, walkErr error) error {
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
			if strings.HasPrefix(p, modulePath+"/app/adapters/") {
				t.Fatalf("contain must not import runtime adapter package: %s imports %s", filepath.Base(path), p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk contain package: %v", err)
	}
}

func TestContainCoreHasNoRuntimeNameBranching(t *testing.T) {
	root := repoRoot(t)
	containDir := filepath.Join(root, "engine", "contain")
	forbidden := []string{`"claude-code"`, `"openclaw"`, `"codex"`}

	err := filepath.WalkDir(containDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(data)
		for _, tok := range forbidden {
			if strings.Contains(src, tok) {
				t.Fatalf("contain must stay runtime-agnostic: %s contains %s", filepath.Base(path), tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk contain package: %v", err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// boundary_test.go sits in engine/contain.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
