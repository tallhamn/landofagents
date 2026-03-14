package runtimehooks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeWriteFile_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-file")
	link := filepath.Join(dir, "symlink")

	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	err := safeWriteFile(link, []byte("malicious"), 0600)
	if err == nil {
		t.Fatal("expected error writing through symlink")
	}

	// Verify original file was not modified.
	data, _ := os.ReadFile(target)
	if string(data) != "original" {
		t.Fatalf("target was modified through symlink: %q", data)
	}
}

func TestSafeWriteFile_AllowsRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	if err := safeWriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("safeWriteFile: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "hello" {
		t.Fatalf("content = %q, want hello", data)
	}
}

func TestSafeCreateDir_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Try to create a child under the symlink.
	err := safeCreateDir(filepath.Join(link, "child"), 0700)
	if err == nil {
		t.Fatal("expected error creating dir through symlink")
	}
}

func TestSafeCreateDir_AllowsNormalPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a", "b", "c")
	if err := safeCreateDir(target, 0700); err != nil {
		t.Fatalf("safeCreateDir: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}
}
