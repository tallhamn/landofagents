package advocate

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/app/codifier"
)

// --- Unit tests (no API key required) ---

func TestGroupDenials(t *testing.T) {
	tests := []struct {
		name       string
		denials    []audit.Record
		wantGroups int
		wantCheck  func([]DenialGroup) string // returns error message or ""
	}{
		{
			name: "single denial",
			denials: []audit.Record{
				{Agent: "goggins", Action: "http:Request", Resource: "api.wrike.com"},
			},
			wantGroups: 1,
			wantCheck: func(gs []DenialGroup) string {
				if gs[0].Agent != "goggins" || gs[0].Service != "wrike.com" {
					return "expected goggins/wrike.com"
				}
				if len(gs[0].Denials) != 1 {
					return "expected 1 denial in group"
				}
				return ""
			},
		},
		{
			name: "same service grouped",
			denials: []audit.Record{
				{Agent: "goggins", Action: "http:Request", Resource: "calendar.google.com"},
				{Agent: "goggins", Action: "http:Request", Resource: "drive.google.com"},
				{Agent: "goggins", Action: "http:Request", Resource: "mail.google.com"},
			},
			wantGroups: 1,
			wantCheck: func(gs []DenialGroup) string {
				if gs[0].Service != "google.com" {
					return "expected service google.com, got " + gs[0].Service
				}
				if len(gs[0].Denials) != 3 {
					return "expected 3 denials in google group"
				}
				return ""
			},
		},
		{
			name: "different services split",
			denials: []audit.Record{
				{Agent: "goggins", Action: "http:Request", Resource: "api.wrike.com"},
				{Agent: "goggins", Action: "http:Request", Resource: "calendar.google.com"},
			},
			wantGroups: 2,
			wantCheck: func(gs []DenialGroup) string {
				services := map[string]bool{}
				for _, g := range gs {
					services[g.Service] = true
				}
				if !services["wrike.com"] || !services["google.com"] {
					return "expected wrike.com and google.com groups"
				}
				return ""
			},
		},
		{
			name: "different agents split",
			denials: []audit.Record{
				{Agent: "goggins", Action: "http:Request", Resource: "api.wrike.com"},
				{Agent: "carmack", Action: "http:Request", Resource: "api.wrike.com"},
			},
			wantGroups: 2,
			wantCheck: func(gs []DenialGroup) string {
				if gs[0].Agent == gs[1].Agent {
					return "expected different agents"
				}
				return ""
			},
		},
		{
			name:       "empty input",
			denials:    nil,
			wantGroups: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := GroupDenials(tt.denials)
			if len(groups) != tt.wantGroups {
				t.Errorf("got %d groups, want %d", len(groups), tt.wantGroups)
			}
			if tt.wantCheck != nil {
				if msg := tt.wantCheck(groups); msg != "" {
					t.Error(msg)
				}
			}
		})
	}
}

func TestExtractService(t *testing.T) {
	tests := []struct {
		resource string
		want     string
	}{
		{"calendar.google.com", "google.com"},
		{"drive.google.com", "google.com"},
		{"api.wrike.com", "wrike.com"},
		{"wrike.com", "wrike.com"},
		{"localhost", "localhost"},
		{"pypi.org", "pypi.org"},
		{"api.openai.com", "openai.com"},
		{"smtp.gmail.com", "gmail.com"},
		{"/etc/hostname", "/etc/hostname"},
		{"", ""},
		{"api.wrike.com:443", "wrike.com"},
		{"a.b.c.d.example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			got := extractService(tt.resource)
			if got != tt.want {
				t.Errorf("extractService(%q) = %q, want %q", tt.resource, got, tt.want)
			}
		})
	}
}

func TestProposeFallback(t *testing.T) {
	denials := []audit.Record{
		{ID: "AUD-000001", Agent: "goggins", Action: "http:Request", Resource: "api.wrike.com"},
		{ID: "AUD-000002", Agent: "goggins", Action: "email:Send", Resource: "user@example.com"},
	}

	proposals := ProposeFallback(denials)

	if len(proposals) != 2 {
		t.Fatalf("got %d proposals, want 2", len(proposals))
	}

	// Should match codifier.DescriptionFromDenial output
	want0 := codifier.DescriptionFromDenial("goggins", "http:Request", "api.wrike.com")
	if proposals[0].Description != want0 {
		t.Errorf("proposal[0].Description = %q, want %q", proposals[0].Description, want0)
	}

	want1 := codifier.DescriptionFromDenial("goggins", "email:Send", "user@example.com")
	if proposals[1].Description != want1 {
		t.Errorf("proposal[1].Description = %q, want %q", proposals[1].Description, want1)
	}

	// Verify denial IDs are carried through
	if proposals[0].DenialIDs[0] != "AUD-000001" {
		t.Errorf("proposal[0].DenialIDs = %v, want [AUD-000001]", proposals[0].DenialIDs)
	}

	// Verify agent is set
	if proposals[0].Agent != "goggins" {
		t.Errorf("proposal[0].Agent = %q, want goggins", proposals[0].Agent)
	}
}

func TestBuildPrompt(t *testing.T) {
	system := buildSystemPrompt()

	// System prompt teaches key concepts
	if !strings.Contains(system, "Advocate") {
		t.Error("system prompt missing Advocate role")
	}
	if !strings.Contains(system, "Minimum scope") {
		t.Error("system prompt missing minimum scope instruction")
	}
	if !strings.Contains(system, "Detect upgrades") {
		t.Error("system prompt missing upgrade detection instruction")
	}
	if !strings.Contains(system, "JSON") {
		t.Error("system prompt missing JSON response format")
	}
	if !strings.Contains(system, "denial_ids") {
		t.Error("system prompt missing denial_ids field")
	}

	// User message includes denial details
	denials := []audit.Record{
		{ID: "AUD-000001", Agent: "goggins", Action: "http:Request", Resource: "api.wrike.com", DenialReason: "no matching policy"},
	}
	existingPerms := []string{"permit(\n  principal,\n  action == Action::\"http:Request\",\n  resource == Resource::\"api.anthropic.com\"\n);"}
	entities := "agents:\n  goggins:\n    image: openclaw/openclaw:latest\n"

	user := buildUserMessage(denials, existingPerms, entities)

	if !strings.Contains(user, "goggins") {
		t.Error("user message missing agent name")
	}
	if !strings.Contains(user, "api.wrike.com") {
		t.Error("user message missing resource")
	}
	if !strings.Contains(user, "AUD-000001") {
		t.Error("user message missing audit ID")
	}
	if !strings.Contains(user, "no matching policy") {
		t.Error("user message missing denial reason")
	}
	if !strings.Contains(user, "api.anthropic.com") {
		t.Error("user message missing existing permissions")
	}
	if !strings.Contains(user, "openclaw/openclaw:latest") {
		t.Error("user message missing entities")
	}
}

func TestBuildPromptMinimal(t *testing.T) {
	denials := []audit.Record{
		{ID: "AUD-000001", Agent: "test", Action: "http:Request", Resource: "example.com"},
	}

	user := buildUserMessage(denials, nil, "")

	if !strings.Contains(user, "example.com") {
		t.Error("user message missing resource")
	}
	// Should not contain sections when empty
	if strings.Contains(user, "Existing permissions") {
		t.Error("user message should not include existing permissions section when empty")
	}
	if strings.Contains(user, "agents.yml") {
		t.Error("user message should not include agents section when empty")
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
	}{
		{
			name: "valid single proposal",
			input: `{
  "proposals": [
    {
      "description": "goggins can make HTTP requests to api.wrike.com",
      "agent": "goggins",
      "denial_ids": ["AUD-000001"],
      "reasoning": "Goggins needs Wrike for project management"
    }
  ]
}`,
			wantCount: 1,
		},
		{
			name: "multiple proposals",
			input: `{
  "proposals": [
    {
      "description": "goggins can make HTTP requests to calendar.google.com and drive.google.com",
      "agent": "goggins",
      "denial_ids": ["AUD-000001", "AUD-000002"],
      "reasoning": "Google services for scheduling"
    },
    {
      "description": "goggins can make HTTP requests to api.wrike.com",
      "agent": "goggins",
      "denial_ids": ["AUD-000003"],
      "reasoning": "Project management"
    }
  ]
}`,
			wantCount: 2,
		},
		{
			name: "with code fence",
			input: "```json\n" + `{
  "proposals": [
    {
      "description": "goggins can access sentry.io",
      "agent": "goggins",
      "denial_ids": ["AUD-000001"],
      "reasoning": "Error reporting"
    }
  ]
}` + "\n```",
			wantCount: 1,
		},
		{
			name:    "empty proposals",
			input:   `{"proposals": []}`,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantErr: true,
		},
		{
			name: "empty description",
			input: `{
  "proposals": [
    {
      "description": "",
      "agent": "goggins",
      "denial_ids": ["AUD-000001"],
      "reasoning": "test"
    }
  ]
}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proposals, err := parseResponse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(proposals) != tt.wantCount {
				t.Errorf("got %d proposals, want %d", len(proposals), tt.wantCount)
			}
		})
	}
}

// --- Integration tests (require ANTHROPIC_API_KEY) ---

func TestProposeIntegration(t *testing.T) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set, skipping integration tests")
	}

	adv := New(apiKey)
	ctx := context.Background()

	entities := `agents:
  goggins:
    image: openclaw/openclaw:latest
    scope: goggins
  carmack:
    image: openclaw/openclaw:latest
    scope: carmack
agent_groups:
  all:
    members: [goggins, carmack]
`

	tests := []struct {
		name  string
		req   ProposalRequest
		check func([]Proposal) string
	}{
		{
			name: "simple HTTP block",
			req: ProposalRequest{
				Denials: []audit.Record{
					{ID: "AUD-000001", Agent: "goggins", Action: "http:Request", Resource: "api.wrike.com"},
				},
				Agent:    "goggins",
				Entities: entities,
			},
			check: func(ps []Proposal) string {
				if len(ps) == 0 {
					return "expected at least 1 proposal"
				}
				d := strings.ToLower(ps[0].Description)
				if !strings.Contains(d, "goggins") {
					return "proposal should mention goggins"
				}
				if !strings.Contains(d, "wrike") {
					return "proposal should mention wrike"
				}
				return ""
			},
		},
		{
			name: "two denials batched",
			req: ProposalRequest{
				Denials: []audit.Record{
					{ID: "AUD-000001", Agent: "goggins", Action: "http:Request", Resource: "calendar.google.com"},
					{ID: "AUD-000002", Agent: "goggins", Action: "http:Request", Resource: "drive.google.com"},
				},
				Agent:    "goggins",
				Entities: entities,
			},
			check: func(ps []Proposal) string {
				if len(ps) == 0 || len(ps) > 2 {
					return "expected 1-2 proposals for related Google denials"
				}
				// At least one proposal should mention Google
				found := false
				for _, p := range ps {
					if strings.Contains(strings.ToLower(p.Description), "google") {
						found = true
					}
				}
				if !found {
					return "at least one proposal should mention google"
				}
				return ""
			},
		},
		{
			name: "existing permission upgrade",
			req: ProposalRequest{
				Denials: []audit.Record{
					{ID: "AUD-000001", Agent: "goggins", Action: "http:Request", Resource: "api.github.com"},
				},
				Agent: "goggins",
				ExistingPerms: []string{
					"// goggins can read from github\npermit(\n  principal == Agent::\"goggins\",\n  action == Action::\"http:Request\",\n  resource == Resource::\"github.com\"\n);",
				},
				Entities: entities,
			},
			check: func(ps []Proposal) string {
				if len(ps) == 0 {
					return "expected at least 1 proposal"
				}
				d := strings.ToLower(ps[0].Description)
				if !strings.Contains(d, "github") {
					return "proposal should mention github"
				}
				return ""
			},
		},
		{
			name: "unexpected access scoped tightly",
			req: ProposalRequest{
				Denials: []audit.Record{
					{ID: "AUD-000001", Agent: "goggins", Action: "http:Request", Resource: "smtp.gmail.com"},
				},
				Agent:    "goggins",
				Entities: entities,
			},
			check: func(ps []Proposal) string {
				if len(ps) == 0 {
					return "expected at least 1 proposal"
				}
				d := strings.ToLower(ps[0].Description)
				if !strings.Contains(d, "smtp") && !strings.Contains(d, "gmail") {
					return "proposal should mention smtp or gmail"
				}
				return ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proposals, err := adv.Propose(ctx, tt.req)
			if err != nil {
				t.Fatalf("Propose(): %v", err)
			}

			for i, p := range proposals {
				t.Logf("Proposal %d: %q (reasoning: %s)", i, p.Description, p.Reasoning)
			}

			if msg := tt.check(proposals); msg != "" {
				t.Error(msg)
			}
		})
	}
}

// TestProposeEndToEnd verifies the full pipeline: Advocate → Codifier → valid Cedar.
func TestProposeEndToEnd(t *testing.T) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set, skipping integration tests")
	}

	adv := New(apiKey)
	cod := codifier.New(apiKey)
	ctx := context.Background()

	entities := `agents:
  goggins:
    image: openclaw/openclaw:latest
    scope: goggins
agent_groups:
  all:
    members: [goggins]
`

	req := ProposalRequest{
		Denials: []audit.Record{
			{ID: "AUD-000001", Agent: "goggins", Action: "http:Request", Resource: "api.myfitnesspal.com"},
		},
		Agent:    "goggins",
		Entities: entities,
	}

	proposals, err := adv.Propose(ctx, req)
	if err != nil {
		t.Fatalf("Advocate.Propose(): %v", err)
	}

	if len(proposals) == 0 {
		t.Fatal("no proposals returned")
	}

	// Feed each proposal through Codifier
	cctx := codifier.CompileContext{Entities: entities}
	entitiesJSON := buildTestEntities(t)

	for i, p := range proposals {
		t.Logf("Proposal %d: %q → compiling...", i, p.Description)

		result, err := cod.Compile(ctx, codifier.CompileRequest{
			Description: p.Description,
			Agent:       p.Agent,
		}, cctx)
		if err != nil {
			t.Errorf("Codifier.Compile(%q): %v", p.Description, err)
			continue
		}

		for _, pol := range result.Policies {
			t.Logf("  Policy (%s):\n%s", pol.Filename, pol.Cedar)

			// Verify it evaluates correctly
			ps, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(pol.Cedar))
			if err != nil {
				t.Errorf("  invalid Cedar: %v", err)
				continue
			}

			var em cedar.EntityMap
			if err := json.Unmarshal(entitiesJSON, &em); err != nil {
				t.Fatalf("parse entities: %v", err)
			}

			principal := cedar.NewEntityUID(cedar.EntityType("Agent"), cedar.String("goggins"))
			action := cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("http:Request"))
			resource := cedar.NewEntityUID(cedar.EntityType("Resource"), cedar.String("api.myfitnesspal.com"))

			decision, _ := cedar.Authorize(ps, em, cedar.Request{
				Principal: principal,
				Action:    action,
				Resource:  resource,
				Context:   cedar.NewRecord(cedar.RecordMap{}),
			})

			if decision != cedar.Allow {
				t.Errorf("  expected permit for goggins → api.myfitnesspal.com, got deny\n  Cedar: %s", pol.Cedar)
			}
		}
	}
}

func buildTestEntities(t *testing.T) []byte {
	t.Helper()

	entities := []map[string]any{
		{"uid": map[string]string{"type": "AgentGroup", "id": "all"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Agent", "id": "goggins"}, "attrs": map[string]any{}, "parents": []any{map[string]string{"type": "AgentGroup", "id": "all"}}},
		{"uid": map[string]string{"type": "Resource", "id": "api.myfitnesspal.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "api.wrike.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "calendar.google.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "drive.google.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "api.github.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "smtp.gmail.com"}, "attrs": map[string]any{}, "parents": []any{}},
	}

	data, err := json.Marshal(entities)
	if err != nil {
		t.Fatalf("marshal test entities: %v", err)
	}
	return data
}
