package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateAndList(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	// Create agents
	if err := m.Create("goggins", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create goggins: %v", err)
	}
	if err := m.Create("carmack", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create carmack: %v", err)
	}

	// List agents
	agents, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}

	// Find goggins
	found := false
	for _, a := range agents {
		if a.Name == "goggins" {
			found = true
			if a.Runtime != "claude-code" {
				t.Errorf("goggins runtime: got %q", a.Runtime)
			}
			if a.Scope != "goggins" {
				t.Errorf("goggins scope: got %q", a.Scope)
			}
		}
	}
	if !found {
		t.Error("goggins not found in list")
	}
}

func TestCreateRequiresRuntime(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	err := m.Create("legacy", CreateOpts{})
	if err == nil {
		t.Fatal("expected create to fail without runtime")
	}
	if !strings.Contains(err.Error(), "requires runtime") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGet(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	m.Create("goggins", CreateOpts{Runtime: "claude-code"})

	a, err := m.Get("goggins")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if a.Name != "goggins" {
		t.Errorf("name: got %q", a.Name)
	}
	if a.Runtime != "claude-code" {
		t.Errorf("runtime: got %q", a.Runtime)
	}
}

func TestGetNotFound(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	_, err := m.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestCreateDuplicate(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	m.Create("goggins", CreateOpts{Runtime: "claude-code"})
	err := m.Create("goggins", CreateOpts{Runtime: "claude-code"})
	if err == nil {
		t.Error("expected error for duplicate agent")
	}
	if !strings.Contains(err.Error(), "loa agent delete goggins") {
		t.Errorf("duplicate error should mention delete command, got: %v", err)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	m.Create("goggins", CreateOpts{Runtime: "claude-code"})
	m.Create("carmack", CreateOpts{Runtime: "claude-code"})

	// Create a fake workspace and runtime policy
	wsDir := filepath.Join(dir, "workspaces", "goggins")
	os.MkdirAll(wsDir, 0755)
	os.WriteFile(filepath.Join(wsDir, "test.txt"), []byte("hello"), 0644)

	policyDir := filepath.Join(dir, "policies", "active")
	os.MkdirAll(policyDir, 0755)
	policyFile := filepath.Join(policyDir, "_runtime-goggins.cedar")
	os.WriteFile(policyFile, []byte("permit(principal, action, resource);"), 0644)

	if err := m.Delete("goggins"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Agent should be gone
	_, err := m.Get("goggins")
	if err == nil {
		t.Error("expected error for deleted agent")
	}

	// Other agent should still exist
	a, err := m.Get("carmack")
	if err != nil {
		t.Fatalf("carmack should still exist: %v", err)
	}
	if a.Name != "carmack" {
		t.Errorf("expected carmack, got %q", a.Name)
	}

	// Workspace should be cleaned up
	if _, err := os.Stat(wsDir); !os.IsNotExist(err) {
		t.Error("workspace dir should be deleted")
	}

	// Runtime policy should be cleaned up
	if _, err := os.Stat(policyFile); !os.IsNotExist(err) {
		t.Error("runtime policy file should be deleted")
	}

	// Agent group should not contain goggins
	data, _ := os.ReadFile(filepath.Join(dir, "config", "agents.yml"))
	content := string(data)
	if strings.Contains(content, "goggins") {
		t.Error("agents.yml should not contain goggins after delete")
	}
}

func TestDeleteNotFound(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	err := m.Delete("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent agent")
	}
}

func TestAgentGroupMembership(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	m.Create("goggins", CreateOpts{Runtime: "claude-code"})
	m.Create("carmack", CreateOpts{Runtime: "claude-code"})

	// Read raw YAML and verify group membership
	data, err := os.ReadFile(filepath.Join(dir, "config", "agents.yml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)
	// The agent group should contain both agents
	if !contains(content, "goggins") || !contains(content, "carmack") {
		t.Errorf("agents.yml doesn't contain both agents in group: %s", content)
	}
}

func TestLegacyEntitiesYAMLIsIgnored(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	legacy := filepath.Join(configDir, "entities.yml")
	if err := os.WriteFile(legacy, []byte(`agents:
  goggins:
    runtime: claude-code
    scope: goggins
agent_groups:
  agent:
    members: [goggins]
`), 0644); err != nil {
		t.Fatalf("write legacy entities.yml: %v", err)
	}

	m := NewManager(dir)
	_, err := m.Get("goggins")
	if err == nil {
		t.Fatalf("expected goggins lookup to fail when only entities.yml exists")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	// Create with one manager instance
	m1 := NewManager(dir)
	m1.Create("goggins", CreateOpts{Runtime: "claude-code"})

	// Read with a new manager instance
	m2 := NewManager(dir)
	agents, err := m2.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].Name != "goggins" {
		t.Errorf("name: got %q", agents[0].Name)
	}
}

func TestEmptyKit(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	// List on empty kit should return empty list, not error
	agents, err := m.List()
	if err != nil {
		t.Fatalf("List on empty: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

func TestAddRememberedVolume(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	if err := m.Create("goggins", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create goggins: %v", err)
	}

	v := "/Users/marcus/project:/workspace/project:ro"
	if err := m.AddRememberedVolume("goggins", v); err != nil {
		t.Fatalf("AddRememberedVolume: %v", err)
	}
	// idempotent
	if err := m.AddRememberedVolume("goggins", v); err != nil {
		t.Fatalf("AddRememberedVolume second: %v", err)
	}

	a, err := m.Get("goggins")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(a.RememberedVolumes) != 1 || a.RememberedVolumes[0] != v {
		t.Fatalf("RememberedVolumes = %v, want [%q]", a.RememberedVolumes, v)
	}
}

func TestRemoveRememberedVolume(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	if err := m.Create("goggins", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create goggins: %v", err)
	}

	v1 := "/Users/marcus/project:/workspace/project:ro"
	v2 := "/Users/marcus/other:/workspace/other"
	if err := m.AddRememberedVolume("goggins", v1); err != nil {
		t.Fatalf("AddRememberedVolume v1: %v", err)
	}
	if err := m.AddRememberedVolume("goggins", v2); err != nil {
		t.Fatalf("AddRememberedVolume v2: %v", err)
	}

	if err := m.RemoveRememberedVolume("goggins", v1); err != nil {
		t.Fatalf("RemoveRememberedVolume: %v", err)
	}

	a, err := m.Get("goggins")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(a.RememberedVolumes) != 1 || a.RememberedVolumes[0] != v2 {
		t.Fatalf("RememberedVolumes = %v, want [%q]", a.RememberedVolumes, v2)
	}
}

func TestAddRememberedVolumeAll(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	if err := m.Create("goggins", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create goggins: %v", err)
	}
	if err := m.Create("carmack", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create carmack: %v", err)
	}

	v := "/Users/marcus/project:/workspace/project:ro"
	if err := m.AddRememberedVolumeAll(v); err != nil {
		t.Fatalf("AddRememberedVolumeAll: %v", err)
	}
	// idempotent
	if err := m.AddRememberedVolumeAll(v); err != nil {
		t.Fatalf("AddRememberedVolumeAll second: %v", err)
	}

	for _, name := range []string{"goggins", "carmack"} {
		a, err := m.Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}
		if len(a.RememberedVolumes) != 1 || a.RememberedVolumes[0] != v {
			t.Fatalf("%s RememberedVolumes = %v, want [%q]", name, a.RememberedVolumes, v)
		}
	}
}

func TestAddAndRemoveAllowedSecret(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	if err := m.Create("goggins", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create goggins: %v", err)
	}

	if err := m.AddAllowedSecret("goggins", "telegram.bot_token"); err != nil {
		t.Fatalf("AddAllowedSecret: %v", err)
	}
	// idempotent
	if err := m.AddAllowedSecret("goggins", "telegram.bot_token"); err != nil {
		t.Fatalf("AddAllowedSecret second: %v", err)
	}

	a, err := m.Get("goggins")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(a.AllowedSecrets) != 1 || a.AllowedSecrets[0] != "telegram.bot_token" {
		t.Fatalf("AllowedSecrets = %v, want [telegram.bot_token]", a.AllowedSecrets)
	}

	if err := m.RemoveAllowedSecret("goggins", "telegram.bot_token"); err != nil {
		t.Fatalf("RemoveAllowedSecret: %v", err)
	}
	a, err = m.Get("goggins")
	if err != nil {
		t.Fatalf("Get after remove: %v", err)
	}
	if len(a.AllowedSecrets) != 0 {
		t.Fatalf("AllowedSecrets after remove = %v, want empty", a.AllowedSecrets)
	}
}

func TestAddNeverMountDir(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	if err := m.Create("goggins", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create goggins: %v", err)
	}

	d := "/Users/marcus/project"
	if err := m.AddNeverMountDir("goggins", d); err != nil {
		t.Fatalf("AddNeverMountDir: %v", err)
	}
	// idempotent
	if err := m.AddNeverMountDir("goggins", d); err != nil {
		t.Fatalf("AddNeverMountDir second: %v", err)
	}

	a, err := m.Get("goggins")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(a.NeverMountDirs) != 1 || a.NeverMountDirs[0] != d {
		t.Fatalf("NeverMountDirs = %v, want [%q]", a.NeverMountDirs, d)
	}
}

func TestAddNeverMountDirAll(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	if err := m.Create("goggins", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create goggins: %v", err)
	}
	if err := m.Create("carmack", CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("Create carmack: %v", err)
	}

	d := "/Users/marcus/project"
	if err := m.AddNeverMountDirAll(d); err != nil {
		t.Fatalf("AddNeverMountDirAll: %v", err)
	}
	// idempotent
	if err := m.AddNeverMountDirAll(d); err != nil {
		t.Fatalf("AddNeverMountDirAll second: %v", err)
	}

	for _, name := range []string{"goggins", "carmack"} {
		a, err := m.Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}
		if len(a.NeverMountDirs) != 1 || a.NeverMountDirs[0] != d {
			t.Fatalf("%s NeverMountDirs = %v, want [%q]", name, a.NeverMountDirs, d)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
