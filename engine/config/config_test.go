package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "kit")
}

func TestLoadKit(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	// Verify agents loaded
	if len(kit.Entities.Agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(kit.Entities.Agents))
	}

	goggins, err := kit.GetAgent("goggins")
	if err != nil {
		t.Fatalf("GetAgent(goggins): %v", err)
	}
	if goggins.Runtime != "claude-code" {
		t.Errorf("goggins runtime: got %q, want %q", goggins.Runtime, "claude-code")
	}
	if goggins.Scope != "goggins" {
		t.Errorf("goggins scope: got %q, want %q", goggins.Scope, "goggins")
	}
	if goggins.Name != "goggins" {
		t.Errorf("goggins name: got %q, want %q", goggins.Name, "goggins")
	}
	if len(goggins.Volumes) != 1 {
		t.Errorf("goggins volumes: got %d, want 1", len(goggins.Volumes))
	}

	carmack, err := kit.GetAgent("carmack")
	if err != nil {
		t.Fatalf("GetAgent(carmack): %v", err)
	}
	if carmack.Runtime != "claude-code" {
		t.Errorf("carmack runtime: got %q, want %q", carmack.Runtime, "claude-code")
	}

	// Verify unknown agent returns error
	_, err = kit.GetAgent("unknown")
	if err == nil {
		t.Error("expected error for unknown agent")
	}
}

func TestLoadProtector(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	if len(kit.Protector.ToolMappings) == 0 {
		t.Fatal("expected tool mappings, got none")
	}

	// Check first mapping
	first := kit.Protector.ToolMappings[0]
	if first.Executable != "cat" {
		t.Errorf("first mapping executable: got %q, want %q", first.Executable, "cat")
	}
	if first.Action != "fs:Read" {
		t.Errorf("first mapping action: got %q, want %q", first.Action, "fs:Read")
	}

	// Check curl mapping has context extractors
	var curlMapping *ToolMapping
	for i, m := range kit.Protector.ToolMappings {
		if m.Executable == "curl" {
			curlMapping = &kit.Protector.ToolMappings[i]
			break
		}
	}
	if curlMapping == nil {
		t.Fatal("curl mapping not found")
	}
	if curlMapping.ContextExtractors["http_method"] != "method_from_curl_args" {
		t.Errorf("curl context_extractors[http_method]: got %q", curlMapping.ContextExtractors["http_method"])
	}

	// Check default_unmapped
	if kit.Protector.DefaultUnmapped != "permit" {
		t.Errorf("default_unmapped: got %q, want %q", kit.Protector.DefaultUnmapped, "permit")
	}

	// Check shell observation patterns
	var observedPatterns []string
	for _, m := range kit.Protector.ToolMappings {
		if m.Action == "__observe_always" {
			observedPatterns = append(observedPatterns, m.Pattern)
		}
	}
	if len(observedPatterns) != 3 {
		t.Errorf("expected 3 shell observation patterns, got %d: %v", len(observedPatterns), observedPatterns)
	}
}

func TestLoadAlwaysAllowed(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	if kit.AlwaysAllowedCedar == "" {
		t.Fatal("always-allowed.cedar is empty")
	}
	if len(kit.AlwaysAllowedCedar) < 10 {
		t.Errorf("always-allowed.cedar suspiciously short: %d bytes", len(kit.AlwaysAllowedCedar))
	}
}

func TestLoadPolicies(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	if len(kit.Policies) != 1 {
		t.Fatalf("expected 1 policy file, got %d", len(kit.Policies))
	}
}

func TestLoadPolicies_IgnoresStaged(t *testing.T) {
	kitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(kitDir, "config"), 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(kitDir, "policies", "active"), 0755); err != nil {
		t.Fatalf("mkdir policies/active: %v", err)
	}

	if err := os.WriteFile(filepath.Join(kitDir, "config", "agents.yml"), []byte(`agents:
  goggins:
    runtime: claude-code
    scope: goggins
agent_groups:
  agent:
    members: [goggins]
recipient_groups: {}
`), 0644); err != nil {
		t.Fatalf("write agents.yml: %v", err)
	}

	if err := os.WriteFile(filepath.Join(kitDir, "config", "protector.yml"), []byte(`tool_mappings: []
default_unmapped: permit
audit:
  log_dir: audit/
  format: jsonl
  log_permitted: true
  log_denied: true
  log_always_allowed: false
`), 0644); err != nil {
		t.Fatalf("write protector.yml: %v", err)
	}

	if err := os.WriteFile(filepath.Join(kitDir, "config", "always-allowed.cedar"), []byte("permit(principal, action, resource);"), 0644); err != nil {
		t.Fatalf("write always-allowed.cedar: %v", err)
	}

	activeFile := filepath.Join(kitDir, "policies", "active", "active.cedar")
	rootFile := filepath.Join(kitDir, "policies", "runtime.cedar")
	for _, f := range []string{activeFile, rootFile} {
		if err := os.WriteFile(f, []byte("permit(principal, action, resource);"), 0644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	kit, err := LoadKit(kitDir)
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	seen := map[string]bool{}
	for _, p := range kit.Policies {
		seen[p] = true
	}
	if !seen[activeFile] {
		t.Fatalf("missing active policy %s in loaded set: %v", activeFile, kit.Policies)
	}
	if seen[rootFile] {
		t.Fatalf("root policy should not be loaded for enforcement: %s", rootFile)
	}
}

func TestLoadKit_RequiresAgentsYAML(t *testing.T) {
	kitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(kitDir, "config"), 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kitDir, "config", "entities.yml"), []byte(`agents:
  legacy:
    runtime: claude-code
    scope: legacy
agent_groups:
  agent:
    members: [legacy]
recipient_groups: {}
`), 0644); err != nil {
		t.Fatalf("write entities.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kitDir, "config", "protector.yml"), []byte(`tool_mappings: []
default_unmapped: permit
audit:
  log_dir: audit/
  format: jsonl
  log_permitted: true
  log_denied: true
  log_always_allowed: false
`), 0644); err != nil {
		t.Fatalf("write protector.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kitDir, "config", "always-allowed.cedar"), []byte("permit(principal, action, resource);"), 0644); err != nil {
		t.Fatalf("write always-allowed.cedar: %v", err)
	}

	_, err := LoadKit(kitDir)
	if err == nil {
		t.Fatalf("expected LoadKit to fail when config/agents.yml is missing")
	}
}

func TestLoadKit_RejectsYAMLPolicyFiles(t *testing.T) {
	kitDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(kitDir, "config"), 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(kitDir, "policies", "active"), 0755); err != nil {
		t.Fatalf("mkdir policies/active: %v", err)
	}

	if err := os.WriteFile(filepath.Join(kitDir, "config", "agents.yml"), []byte(`agents:
  goggins:
    runtime: claude-code
    scope: goggins
agent_groups:
  agent:
    members: [goggins]
recipient_groups: {}
`), 0644); err != nil {
		t.Fatalf("write agents.yml: %v", err)
	}

	if err := os.WriteFile(filepath.Join(kitDir, "config", "protector.yml"), []byte(`tool_mappings: []
default_unmapped: permit
audit:
  log_dir: audit/
  format: jsonl
  log_permitted: true
  log_denied: true
  log_always_allowed: false
`), 0644); err != nil {
		t.Fatalf("write protector.yml: %v", err)
	}

	if err := os.WriteFile(filepath.Join(kitDir, "config", "always-allowed.cedar"), []byte("permit(principal, action, resource);"), 0644); err != nil {
		t.Fatalf("write always-allowed.cedar: %v", err)
	}

	if err := os.WriteFile(filepath.Join(kitDir, "policies", "active", "bad.yml"), []byte("not: cedar"), 0644); err != nil {
		t.Fatalf("write bad policy: %v", err)
	}

	_, err := LoadKit(kitDir)
	if err == nil {
		t.Fatal("expected LoadKit to fail on YAML policy file")
	}
}

func TestEntityGroups(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	// Check agent groups
	agentGroup, ok := kit.Entities.AgentGroups["agent"]
	if !ok {
		t.Fatal("agent group 'agent' not found")
	}
	if len(agentGroup.Members) != 2 {
		t.Errorf("agent group members: got %d, want 2", len(agentGroup.Members))
	}

	// Check recipient groups
	familyGroup, ok := kit.Entities.RecipientGroups["family"]
	if !ok {
		t.Fatal("recipient group 'family' not found")
	}
	if len(familyGroup.Members) != 2 {
		t.Errorf("family group members: got %d, want 2", len(familyGroup.Members))
	}
}

func TestEntitiesToCedarJSON(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	data, err := kit.Entities.EntitiesToCedarJSON()
	if err != nil {
		t.Fatalf("EntitiesToCedarJSON: %v", err)
	}

	// Verify it's valid JSON
	var entities []CedarEntity
	if err := json.Unmarshal(data, &entities); err != nil {
		t.Fatalf("unmarshal Cedar JSON: %v", err)
	}

	// Should have: 2 agents + 1 agent group + 1 recipient group + 2 recipients = 6
	if len(entities) != 6 {
		t.Errorf("expected 6 Cedar entities, got %d", len(entities))
		for _, e := range entities {
			t.Logf("  %s::%s (parents: %v)", e.UID.Type, e.UID.ID, e.Parents)
		}
	}

	// Verify agent entities have correct parents
	for _, e := range entities {
		if e.UID.Type == "Agent" {
			if len(e.Parents) == 0 {
				t.Errorf("Agent %q has no parents, expected AgentGroup", e.UID.ID)
			}
			for _, p := range e.Parents {
				if p.Type != "AgentGroup" {
					t.Errorf("Agent %q parent type: got %q, want AgentGroup", e.UID.ID, p.Type)
				}
			}
		}
	}

	// Verify recipient entities have correct parents
	for _, e := range entities {
		if e.UID.Type == "Recipient" {
			if len(e.Parents) == 0 {
				t.Errorf("Recipient %q has no parents", e.UID.ID)
			}
			for _, p := range e.Parents {
				if p.Type != "RecipientGroup" {
					t.Errorf("Recipient %q parent type: got %q, want RecipientGroup", e.UID.ID, p.Type)
				}
			}
		}
	}
}

func TestLoadAgentRuntime(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	rt, err := kit.LoadAgentRuntime("goggins")
	if err != nil {
		t.Fatalf("LoadAgentRuntime: %v", err)
	}

	if rt.Name != "claude-code" {
		t.Errorf("runtime name: got %q, want %q", rt.Name, "claude-code")
	}
	if rt.Build == nil {
		t.Fatal("expected Build to be set")
	}
	if rt.BaseCedar == "" {
		t.Error("expected base_cedar to be set")
	}
}

func TestLoadAgentRuntimeNotFound(t *testing.T) {
	kit, err := LoadKit(testdataDir())
	if err != nil {
		t.Fatalf("LoadKit: %v", err)
	}

	_, err = kit.LoadAgentRuntime("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent agent runtime")
	}
}
