package contain

import (
	"os"
	"path/filepath"
	"strings"
)

func findModuleRoot() string {
	cwd, _ := os.Getwd()
	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		// Resolve symlinks so `go install` binaries trace back to source.
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exeDir = filepath.Dir(resolved)
		} else {
			exeDir = filepath.Dir(exe)
		}
	}
	return resolveModuleRoot(cwd, os.Getenv("LOA_SOURCE_DIR"), exeDir)
}

func resolveModuleRoot(startDir, overrideDir, exeDir string) string {
	if root := cleanIfModuleRoot(overrideDir); root != "" {
		return root
	}
	if root := findModuleRootUpward(startDir); root != "" {
		return root
	}
	if root := findModuleRootDownward(startDir, 3); root != "" {
		return root
	}
	if root := findModuleRootUpward(exeDir); root != "" {
		return root
	}
	// If the kit dir is set, the source tree is often a sibling or parent.
	if kitDir := os.Getenv("LOA_KIT"); kitDir != "" {
		if root := findModuleRootUpward(kitDir); root != "" {
			return root
		}
	}
	return "."
}

func cleanIfModuleRoot(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	clean := filepath.Clean(dir)
	if isModuleRoot(clean) {
		return clean
	}
	return ""
}

func findModuleRootUpward(startDir string) string {
	if strings.TrimSpace(startDir) == "" {
		return ""
	}
	dir := filepath.Clean(startDir)
	for {
		if isModuleRoot(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func findModuleRootDownward(startDir string, maxDepth int) string {
	if strings.TrimSpace(startDir) == "" || maxDepth < 0 {
		return ""
	}
	type node struct {
		dir   string
		depth int
	}
	queue := []node{{dir: filepath.Clean(startDir), depth: 0}}
	seen := map[string]bool{}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if seen[n.dir] {
			continue
		}
		seen[n.dir] = true
		if isModuleRoot(n.dir) {
			return n.dir
		}
		if n.depth >= maxDepth {
			continue
		}
		entries, err := os.ReadDir(n.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if shouldSkipModuleSearchDir(name) {
				continue
			}
			queue = append(queue, node{dir: filepath.Join(n.dir, name), depth: n.depth + 1})
		}
	}
	return ""
}

func shouldSkipModuleSearchDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", ".idea", ".vscode":
		return true
	default:
		return false
	}
}

func isModuleRoot(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "cmd", "loa", "main.go")); err != nil {
		return false
	}
	return true
}
