package runtimehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexHookPrepare_CreatesPrivateConfigDir(t *testing.T) {
	hook := codexHook{}
	workspaceDir := t.TempDir()

	out, err := hook.Prepare(PrepareInput{
		WorkspaceDir: workspaceDir,
		RuntimeEnv:   []string{"OPENAI_API_KEY"},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(out.RuntimeEnv) != 1 || out.RuntimeEnv[0] != "OPENAI_API_KEY" {
		t.Fatalf("RuntimeEnv = %v, want passthrough", out.RuntimeEnv)
	}
	if len(out.AgentVolumes) != 1 {
		t.Fatalf("AgentVolumes = %v", out.AgentVolumes)
	}
	if !strings.HasSuffix(out.AgentVolumes[0], ":"+codexConfigMountTarget) {
		t.Fatalf("AgentVolumes[0] = %q", out.AgentVolumes[0])
	}

	configDir := filepath.Join(workspaceDir, ".codex")
	info, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("config dir mode = %o, want 700", info.Mode().Perm())
	}
}

func TestCodexHookPrepare_SeedsAuthWithPrivatePermissions(t *testing.T) {
	hook := codexHook{}
	home := t.TempDir()
	t.Setenv("HOME", home)

	hostConfigDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(hostConfigDir, 0o700); err != nil {
		t.Fatalf("mkdir host codex dir: %v", err)
	}
	hostAuthPath := filepath.Join(hostConfigDir, "auth.json")
	hostAuthData := []byte(`{"access_token":"test-token"}`)
	if err := os.WriteFile(hostAuthPath, hostAuthData, 0o600); err != nil {
		t.Fatalf("write host auth: %v", err)
	}

	workspaceDir := t.TempDir()
	if _, err := hook.Prepare(PrepareInput{WorkspaceDir: workspaceDir}); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	destAuthPath := filepath.Join(workspaceDir, ".codex", "auth.json")
	data, err := os.ReadFile(destAuthPath)
	if err != nil {
		t.Fatalf("read seeded auth: %v", err)
	}
	if string(data) != string(hostAuthData) {
		t.Fatalf("seeded auth = %q, want %q", string(data), string(hostAuthData))
	}

	info, err := os.Stat(destAuthPath)
	if err != nil {
		t.Fatalf("stat seeded auth: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("auth.json mode = %o, want 600", info.Mode().Perm())
	}
}
