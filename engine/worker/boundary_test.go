package worker_test

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

func TestWorkerDoesNotImportAdapters(t *testing.T) {
	root := repoRoot(t)
	workerDir := filepath.Join(root, "engine", "worker")

	fset := token.NewFileSet()
	err := filepath.WalkDir(workerDir, func(path string, d os.DirEntry, walkErr error) error {
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
				t.Fatalf("worker must not import adapter package: %s imports %s", filepath.Base(path), p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk worker package: %v", err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// boundary_test.go sits in engine/worker.
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
