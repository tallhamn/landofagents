package protector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTestPolicy creates a .cedar file in the given dir and returns its path.
func writeTestPolicy(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy %s: %v", name, err)
	}
	return path
}

func TestCedarPermit(t *testing.T) {
	dir := t.TempDir()

	policyPath := writeTestPolicy(t, dir, "always-allowed.cedar", `
permit(
  principal == Agent::"goggins",
  action == Action::"fs:Read",
  resource
);
`)

	entities := []map[string]any{
		{"uid": map[string]string{"type": "Agent", "id": "goggins"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "/etc/hostname"}, "attrs": map[string]any{}, "parents": []any{}},
	}
	entitiesJSON, _ := json.Marshal(entities)

	eval, err := NewCedarEvaluator([]string{policyPath}, entitiesJSON)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	defer eval.Cleanup()

	decision, err := eval.Evaluate(CedarRequest{
		Principal: `Agent::"goggins"`,
		Action:    `Action::"fs:Read"`,
		Resource:  `Resource::"/etc/hostname"`,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision != CedarPermit {
		t.Errorf("decision: got %q, want %q", decision, CedarPermit)
	}
}

func TestCedarDeny(t *testing.T) {
	dir := t.TempDir()

	policyPath := writeTestPolicy(t, dir, "always-allowed.cedar", `
permit(
  principal == Agent::"goggins",
  action == Action::"fs:Read",
  resource
);
`)

	entities := []map[string]any{
		{"uid": map[string]string{"type": "Agent", "id": "goggins"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Agent", "id": "carmack"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "/etc/hostname"}, "attrs": map[string]any{}, "parents": []any{}},
	}
	entitiesJSON, _ := json.Marshal(entities)

	eval, err := NewCedarEvaluator([]string{policyPath}, entitiesJSON)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	defer eval.Cleanup()

	// carmack is not permitted by the policy
	decision, err := eval.Evaluate(CedarRequest{
		Principal: `Agent::"carmack"`,
		Action:    `Action::"fs:Read"`,
		Resource:  `Resource::"/etc/hostname"`,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision != CedarDeny {
		t.Errorf("decision: got %q, want %q", decision, CedarDeny)
	}
}

func TestCedarGroupMembership(t *testing.T) {
	dir := t.TempDir()

	policyPath := writeTestPolicy(t, dir, "group-policy.cedar", `
permit(
  principal in AgentGroup::"agent",
  action == Action::"fs:Read",
  resource
);
`)

	entities := []map[string]any{
		{"uid": map[string]string{"type": "AgentGroup", "id": "agent"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Agent", "id": "goggins"}, "attrs": map[string]any{}, "parents": []any{map[string]string{"type": "AgentGroup", "id": "agent"}}},
		{"uid": map[string]string{"type": "Resource", "id": "file.txt"}, "attrs": map[string]any{}, "parents": []any{}},
	}
	entitiesJSON, _ := json.Marshal(entities)

	eval, err := NewCedarEvaluator([]string{policyPath}, entitiesJSON)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	defer eval.Cleanup()

	// goggins is in AgentGroup::"agent", should be permitted
	decision, err := eval.Evaluate(CedarRequest{
		Principal: `Agent::"goggins"`,
		Action:    `Action::"fs:Read"`,
		Resource:  `Resource::"file.txt"`,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision != CedarPermit {
		t.Errorf("decision: got %q, want %q", decision, CedarPermit)
	}
}

func TestCedarForbid(t *testing.T) {
	dir := t.TempDir()

	permitPath := writeTestPolicy(t, dir, "permit.cedar", `
permit(
  principal in AgentGroup::"agent",
  action == Action::"http:Request",
  resource
);
`)
	forbidPath := writeTestPolicy(t, dir, "forbid.cedar", `
forbid(
  principal in AgentGroup::"agent",
  action == Action::"http:Request",
  resource == Resource::"evil.com"
);
`)

	entities := []map[string]any{
		{"uid": map[string]string{"type": "AgentGroup", "id": "agent"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Agent", "id": "goggins"}, "attrs": map[string]any{}, "parents": []any{map[string]string{"type": "AgentGroup", "id": "agent"}}},
		{"uid": map[string]string{"type": "Resource", "id": "api.wrike.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "evil.com"}, "attrs": map[string]any{}, "parents": []any{}},
	}
	entitiesJSON, _ := json.Marshal(entities)

	eval, err := NewCedarEvaluator([]string{permitPath, forbidPath}, entitiesJSON)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	defer eval.Cleanup()

	// wrike.com should be permitted
	decision, err := eval.Evaluate(CedarRequest{
		Principal: `Agent::"goggins"`,
		Action:    `Action::"http:Request"`,
		Resource:  `Resource::"api.wrike.com"`,
	})
	if err != nil {
		t.Fatalf("Evaluate wrike: %v", err)
	}
	if decision != CedarPermit {
		t.Errorf("wrike decision: got %q, want %q", decision, CedarPermit)
	}

	// evil.com should be denied (forbid overrides permit)
	decision, err = eval.Evaluate(CedarRequest{
		Principal: `Agent::"goggins"`,
		Action:    `Action::"http:Request"`,
		Resource:  `Resource::"evil.com"`,
	})
	if err != nil {
		t.Fatalf("Evaluate evil: %v", err)
	}
	if decision != CedarDeny {
		t.Errorf("evil decision: got %q, want %q", decision, CedarDeny)
	}
}

func TestCedarMultiplePolicies(t *testing.T) {
	dir := t.TempDir()

	alwaysPath := writeTestPolicy(t, dir, "always-allowed.cedar", `
permit(
  principal in AgentGroup::"agent",
  action == Action::"fs:Read",
  resource
);
`)
	httpPath := writeTestPolicy(t, dir, "http-permit.cedar", `
permit(
  principal in AgentGroup::"agent",
  action == Action::"http:Request",
  resource == Resource::"api.wrike.com"
);
`)

	entities := []map[string]any{
		{"uid": map[string]string{"type": "AgentGroup", "id": "agent"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Agent", "id": "goggins"}, "attrs": map[string]any{}, "parents": []any{map[string]string{"type": "AgentGroup", "id": "agent"}}},
		{"uid": map[string]string{"type": "Resource", "id": "/etc/hostname"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "api.wrike.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "evil.com"}, "attrs": map[string]any{}, "parents": []any{}},
	}
	entitiesJSON, _ := json.Marshal(entities)

	eval, err := NewCedarEvaluator([]string{alwaysPath, httpPath}, entitiesJSON)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	defer eval.Cleanup()

	tests := []struct {
		name     string
		action   string
		resource string
		want     CedarDecision
	}{
		{"fs read permitted", `Action::"fs:Read"`, `Resource::"/etc/hostname"`, CedarPermit},
		{"http wrike permitted", `Action::"http:Request"`, `Resource::"api.wrike.com"`, CedarPermit},
		{"http evil denied", `Action::"http:Request"`, `Resource::"evil.com"`, CedarDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := eval.Evaluate(CedarRequest{
				Principal: `Agent::"goggins"`,
				Action:    tt.action,
				Resource:  tt.resource,
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if decision != tt.want {
				t.Errorf("decision: got %q, want %q", decision, tt.want)
			}
		})
	}
}
