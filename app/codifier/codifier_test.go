package codifier

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

// --- Unit tests (no API key required) ---

func TestBuildPrompt(t *testing.T) {
	req := CompileRequest{
		Description: "goggins can access api.wrike.com",
		Agent:       "goggins",
	}
	cctx := CompileContext{
		Entities: "agents:\n  goggins:\n    image: openclaw/openclaw:latest\n",
		Existing: []string{
			"permit(\n  principal,\n  action == Action::\"http:Request\",\n  resource == Resource::\"api.anthropic.com\"\n);",
		},
	}

	system := buildSystemPrompt()
	user := buildUserMessage(req, cctx)

	// System prompt teaches Cedar syntax
	if !strings.Contains(system, "permit") {
		t.Error("system prompt missing permit keyword")
	}
	if !strings.Contains(system, "http:Request") {
		t.Error("system prompt missing http:Request action")
	}
	if !strings.Contains(system, "JSON") {
		t.Error("system prompt missing JSON response format")
	}

	// User message includes all context
	if !strings.Contains(user, "goggins can access api.wrike.com") {
		t.Error("user message missing description")
	}
	if !strings.Contains(user, "goggins") {
		t.Error("user message missing agent name")
	}
	if !strings.Contains(user, "openclaw/openclaw:latest") {
		t.Error("user message missing entities content")
	}
	if !strings.Contains(user, "api.anthropic.com") {
		t.Error("user message missing existing policies")
	}
}

func TestBuildPromptMinimal(t *testing.T) {
	req := CompileRequest{
		Description: "allow everything",
		Agent:       "test",
	}
	cctx := CompileContext{} // no entities, no existing policies

	user := buildUserMessage(req, cctx)
	if !strings.Contains(user, "allow everything") {
		t.Error("user message missing description")
	}
	// Should not contain entities/existing sections when empty
	if strings.Contains(user, "agents.yml") {
		t.Error("user message should not include agents section when empty")
	}
}

func TestValidateCedar(t *testing.T) {
	tests := []struct {
		name    string
		cedar   string
		wantErr bool
	}{
		{
			name: "valid permit",
			cedar: `permit(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"api.wrike.com"
);`,
			wantErr: false,
		},
		{
			name: "valid forbid",
			cedar: `forbid(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"evil.com"
);`,
			wantErr: false,
		},
		{
			name: "valid bare principal",
			cedar: `permit(
  principal,
  action == Action::"http:Request",
  resource == Resource::"api.anthropic.com"
);`,
			wantErr: false,
		},
		{
			name:    "invalid syntax",
			cedar:   `permit(principal action resource)`,
			wantErr: true,
		},
		{
			name:    "empty string",
			cedar:   "",
			wantErr: false, // cedar-go treats empty input as zero policies (valid)
		},
		{
			name:    "random text",
			cedar:   "this is not cedar",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCedar(tt.cedar)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCedar() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantCount  int
		wantErr    bool
		wantReason string
	}{
		{
			name: "valid single policy",
			input: `{
  "policies": [
    {
      "cedar": "permit(\n  principal == Agent::\"goggins\",\n  action == Action::\"http:Request\",\n  resource == Resource::\"api.wrike.com\"\n);",
      "filename": "goggins-http-wrike.cedar"
    }
  ],
  "reasoning": "Generated permit for wrike access"
}`,
			wantCount:  1,
			wantErr:    false,
			wantReason: "Generated permit for wrike access",
		},
		{
			name: "multiple policies",
			input: `{
  "policies": [
    {
      "cedar": "permit(\n  principal == Agent::\"goggins\",\n  action == Action::\"http:Request\",\n  resource == Resource::\"github.com\"\n);",
      "filename": "goggins-http-github.cedar"
    },
    {
      "cedar": "permit(\n  principal == Agent::\"goggins\",\n  action == Action::\"http:Request\",\n  resource == Resource::\"npmjs.org\"\n);",
      "filename": "goggins-http-npmjs.cedar"
    }
  ],
  "reasoning": "Two domains requested"
}`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "with code fence",
			input: "```json\n" + `{
  "policies": [
    {
      "cedar": "permit(\n  principal,\n  action == Action::\"http:Request\",\n  resource == Resource::\"api.anthropic.com\"\n);",
      "filename": "all-http-anthropic.cedar"
    }
  ],
  "reasoning": "ok"
}` + "\n```",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:    "empty policies array",
			input:   `{"policies": [], "reasoning": "nothing"}`,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			input:   `not json at all`,
			wantErr: true,
		},
		{
			name: "empty cedar field",
			input: `{
  "policies": [{"cedar": "", "filename": "test.cedar"}],
  "reasoning": "bad"
}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseResponse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if len(result.Policies) != tt.wantCount {
				t.Errorf("got %d policies, want %d", len(result.Policies), tt.wantCount)
			}
			if tt.wantReason != "" && result.Reasoning != tt.wantReason {
				t.Errorf("reasoning = %q, want %q", result.Reasoning, tt.wantReason)
			}
		})
	}
}

func TestDescriptionFromDenial(t *testing.T) {
	tests := []struct {
		agent, action, resource string
		want                    string
	}{
		{"goggins", "http:Request", "api.wrike.com", "goggins can make HTTP requests to api.wrike.com"},
		{"carmack", "http:Request", "pypi.org", "carmack can make HTTP requests to pypi.org"},
		{"goggins", "email:Send", "user@example.com", "goggins can send emails to user@example.com"},
		{"goggins", "fs:Read", "/etc/hostname", "goggins can Read /etc/hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.agent+"/"+tt.action, func(t *testing.T) {
			got := DescriptionFromDenial(tt.agent, tt.action, tt.resource)
			if got != tt.want {
				t.Errorf("DescriptionFromDenial() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripCodeFence(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no fence", `{"a":1}`, `{"a":1}`},
		{"json fence", "```json\n{\"a\":1}\n```", `{"a":1}`},
		{"plain fence", "```\n{\"a\":1}\n```", `{"a":1}`},
		{"with whitespace", "  ```json\n{\"a\":1}\n```  ", `{"a":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripCodeFence(tt.input)
			if got != tt.want {
				t.Errorf("stripCodeFence() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Integration tests (require ANTHROPIC_API_KEY) ---

func TestCompileIntegration(t *testing.T) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set, skipping integration tests")
	}

	cod := New(apiKey)
	ctx := context.Background()

	cctx := CompileContext{
		Entities: `agents:
  goggins:
    image: openclaw/openclaw:latest
    scope: goggins
  carmack:
    image: openclaw/openclaw:latest
    scope: carmack
agent_groups:
  all:
    members: [goggins, carmack]
`,
	}

	// Build Cedar entities JSON for evaluation
	entitiesJSON := buildTestEntities(t)

	tests := []struct {
		name        string
		description string
		agent       string
		checks      []evalCheck
	}{
		{
			name:        "single domain permit",
			description: "goggins can access calendar.google.com",
			agent:       "goggins",
			checks: []evalCheck{
				{principal: "goggins", resource: "calendar.google.com", wantPermit: true},
				{principal: "carmack", resource: "calendar.google.com", wantPermit: false},
			},
		},
		{
			name:        "http request explicit",
			description: "goggins can make HTTP requests to api.wrike.com",
			agent:       "goggins",
			checks: []evalCheck{
				{principal: "goggins", resource: "api.wrike.com", wantPermit: true},
				{principal: "goggins", resource: "evil.com", wantPermit: false},
			},
		},
		{
			name:        "all agents",
			description: "all agents can reach the Claude API at api.anthropic.com",
			agent:       "",
			checks: []evalCheck{
				{principal: "goggins", resource: "api.anthropic.com", wantPermit: true},
				{principal: "carmack", resource: "api.anthropic.com", wantPermit: true},
			},
		},
		{
			name:        "forbid",
			description: "goggins cannot access evil.com",
			agent:       "goggins",
			checks: []evalCheck{
				// forbid policy — need a permit-all first, then verify forbid blocks
				{principal: "goggins", resource: "evil.com", wantPermit: false, isForbid: true},
			},
		},
		{
			name:        "two domains",
			description: "goggins can access github.com and npmjs.org",
			agent:       "goggins",
			checks: []evalCheck{
				{principal: "goggins", resource: "github.com", wantPermit: true},
				{principal: "goggins", resource: "npmjs.org", wantPermit: true},
			},
		},
		{
			name:        "forbid all agents",
			description: "no agent can access darkweb.example.com",
			agent:       "",
			checks: []evalCheck{
				{principal: "goggins", resource: "darkweb.example.com", wantPermit: false, isForbid: true},
				{principal: "carmack", resource: "darkweb.example.com", wantPermit: false, isForbid: true},
			},
		},
		{
			name:        "different agent",
			description: "carmack can access pypi.org and crates.io",
			agent:       "carmack",
			checks: []evalCheck{
				{principal: "carmack", resource: "pypi.org", wantPermit: true},
				{principal: "carmack", resource: "crates.io", wantPermit: true},
			},
		},
		{
			name:        "wildcard-ish domain",
			description: "goggins can access any Google API (googleapis.com)",
			agent:       "goggins",
			// This is tricky — Cedar doesn't natively support wildcards.
			// The LLM should generate something for googleapis.com.
			// We just verify it parses and produces a permit for a reasonable resource.
			checks: []evalCheck{
				{principal: "goggins", resource: "googleapis.com", wantPermit: true},
			},
		},
		{
			name:        "with context note",
			description: "goggins can access sentry.io for error reporting",
			agent:       "goggins",
			checks: []evalCheck{
				{principal: "goggins", resource: "sentry.io", wantPermit: true},
			},
		},
		{
			name:        "carmack openai",
			description: "carmack can access api.openai.com",
			agent:       "carmack",
			checks: []evalCheck{
				{principal: "carmack", resource: "api.openai.com", wantPermit: true},
				{principal: "goggins", resource: "api.openai.com", wantPermit: false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cod.Compile(ctx, CompileRequest{
				Description: tt.description,
				Agent:       tt.agent,
			}, cctx)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.description, err)
			}

			if len(result.Policies) == 0 {
				t.Fatal("no policies returned")
			}

			t.Logf("Reasoning: %s", result.Reasoning)
			for _, p := range result.Policies {
				t.Logf("Policy (%s):\n%s", p.Filename, p.Cedar)
			}

			// Validate and evaluate each check
			for _, check := range tt.checks {
				// Combine all generated policies
				var allCedar string
				for _, p := range result.Policies {
					allCedar += p.Cedar + "\n"
				}

				// For forbid checks, we need a broad permit first so the forbid has something to override
				if check.isForbid {
					allCedar = "permit(\n  principal,\n  action == Action::\"http:Request\",\n  resource\n);\n" + allCedar
				}

				evaluateCedarCheck(t, allCedar, entitiesJSON, check)
			}
		})
	}
}

type evalCheck struct {
	principal  string
	resource   string
	wantPermit bool
	isForbid   bool // if true, adds a permit-all before the generated policy
}

func evaluateCedarCheck(t *testing.T, cedarText string, entitiesJSON []byte, check evalCheck) {
	t.Helper()

	ps, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(cedarText))
	if err != nil {
		t.Fatalf("parse Cedar: %v\n%s", err, cedarText)
	}

	var entities cedar.EntityMap
	if err := json.Unmarshal(entitiesJSON, &entities); err != nil {
		t.Fatalf("parse entities: %v", err)
	}

	principal := cedar.NewEntityUID(cedar.EntityType("Agent"), cedar.String(check.principal))
	action := cedar.NewEntityUID(cedar.EntityType("Action"), cedar.String("http:Request"))
	resource := cedar.NewEntityUID(cedar.EntityType("Resource"), cedar.String(check.resource))

	req := cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	}

	decision, _ := cedar.Authorize(ps, entities, req)

	if check.wantPermit && decision != cedar.Allow {
		t.Errorf("expected permit for %s -> %s, got deny\nCedar:\n%s", check.principal, check.resource, cedarText)
	}
	if !check.wantPermit && decision == cedar.Allow {
		t.Errorf("expected deny for %s -> %s, got permit\nCedar:\n%s", check.principal, check.resource, cedarText)
	}
}

func buildTestEntities(t *testing.T) []byte {
	t.Helper()

	entities := []map[string]any{
		{"uid": map[string]string{"type": "AgentGroup", "id": "all"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Agent", "id": "goggins"}, "attrs": map[string]any{}, "parents": []any{map[string]string{"type": "AgentGroup", "id": "all"}}},
		{"uid": map[string]string{"type": "Agent", "id": "carmack"}, "attrs": map[string]any{}, "parents": []any{map[string]string{"type": "AgentGroup", "id": "all"}}},
		// Resources — all domains used in tests
		{"uid": map[string]string{"type": "Resource", "id": "calendar.google.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "api.wrike.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "api.anthropic.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "evil.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "github.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "npmjs.org"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "darkweb.example.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "pypi.org"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "crates.io"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "googleapis.com"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "sentry.io"}, "attrs": map[string]any{}, "parents": []any{}},
		{"uid": map[string]string{"type": "Resource", "id": "api.openai.com"}, "attrs": map[string]any{}, "parents": []any{}},
	}

	data, err := json.Marshal(entities)
	if err != nil {
		t.Fatalf("marshal test entities: %v", err)
	}
	return data
}
