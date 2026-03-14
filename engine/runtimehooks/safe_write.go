package runtimehooks

import (
	"fmt"
	"os"
	"path/filepath"
)

// safeCreateDir creates a directory, rejecting any symlink in the path.
// This prevents a malicious agent workspace from tricking the host-side
// bootstrap into creating directories at attacker-chosen locations.
func safeCreateDir(dir string, perm os.FileMode) error {
	if err := rejectSymlinksInPath(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, perm)
}

// safeWriteFile writes a file, rejecting symlinks at the target path.
// This prevents a malicious workspace symlink from redirecting host writes
// to arbitrary locations.
func safeWriteFile(path string, data []byte, perm os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink: %s", path)
		}
	}
	return os.WriteFile(path, data, perm)
}

// rejectSymlinksInPath walks from the target up to the root and rejects
// any existing path component that is a symlink.
func rejectSymlinksInPath(target string) error {
	cleaned := filepath.Clean(target)
	// Check each existing ancestor for symlinks.
	cur := cleaned
	for {
		info, err := os.Lstat(cur)
		if err != nil {
			// Path component doesn't exist yet — safe, MkdirAll will create it.
			parent := filepath.Dir(cur)
			if parent == cur {
				break
			}
			cur = parent
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to create directory through symlink: %s -> %s", target, cur)
		}
		break
	}
	return nil
}
