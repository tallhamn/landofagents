package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func collectChangedFilesSince(rootDir, snapshotFile string, maxFiles int) ([]string, int, error) {
	rootDir = strings.TrimSpace(rootDir)
	snapshotFile = strings.TrimSpace(snapshotFile)
	if rootDir == "" || snapshotFile == "" {
		return nil, 0, nil
	}

	rootDir = expandHome(rootDir)
	rootDir = filepath.Clean(rootDir)
	rootInfo, err := os.Stat(rootDir)
	if err != nil || !rootInfo.IsDir() {
		return nil, 0, nil
	}
	snapInfo, err := os.Stat(snapshotFile)
	if err != nil {
		return nil, 0, nil
	}
	cutoff := snapInfo.ModTime()

	if maxFiles <= 0 {
		maxFiles = 20
	}

	var changed []string
	err = filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if path != rootDir && shouldIgnoreActivityDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !info.ModTime().After(cutoff) {
			return nil
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		changed = append(changed, rel)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	sort.Strings(changed)
	total := len(changed)
	if total > maxFiles {
		return append([]string{}, changed[:maxFiles]...), total, nil
	}
	return changed, total, nil
}

func shouldIgnoreActivityDir(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case ".git", ".hg", ".svn",
		"node_modules", ".next", ".cache", ".turbo",
		"dist", "build", "target",
		"venv", ".venv", "__pycache__":
		return true
	default:
		return false
	}
}

func snapshotMarkerPath() string {
	return filepath.Join(os.TempDir(), "loa-activity-snapshot-"+time.Now().UTC().Format("20060102150405.000000000"))
}
