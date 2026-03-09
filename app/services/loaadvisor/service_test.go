package loaadvisor

import (
	"strings"
	"testing"
	"time"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/audit"
)

func TestSuggestNetworkHost(t *testing.T) {
	svc := New()
	now := time.Now().UTC()
	result, err := svc.Suggest(SuggestRequest{
		AgentName:    "hackerman",
		Since:        now.Add(-24 * time.Hour),
		NetworkScope: "host",
		Records: []audit.Record{
			{
				Timestamp:    now.Add(-2 * time.Hour),
				Agent:        "hackerman",
				Action:       "http:Request",
				Resource:     "www.slackware.com",
				Decision:     "deny",
				DecisionPath: "policy",
				DenialReason: "No policy permits hackerman to reach www.slackware.com",
			},
			{
				Timestamp:    now.Add(-90 * time.Minute),
				Agent:        "hackerman",
				Action:       "http:Request",
				Resource:     "www.slackware.com",
				Decision:     "deny",
				DecisionPath: "log",
				DenialReason: "No policy permits hackerman to reach www.slackware.com",
			},
			{
				Timestamp:    now.Add(-80 * time.Minute),
				Agent:        "hackerman",
				Action:       "http:Request",
				Resource:     "www.slackware.com",
				Decision:     "deny",
				DecisionPath: "log",
				DenialReason: "temporary dns failure",
			},
		},
	})
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if len(result.Network) != 1 {
		t.Fatalf("network suggestions = %d, want 1", len(result.Network))
	}
	got := result.Network[0]
	if got.Resource != "www.slackware.com" {
		t.Fatalf("resource = %q, want www.slackware.com", got.Resource)
	}
	if got.Count != 2 {
		t.Fatalf("count = %d, want 2", got.Count)
	}
	if len(got.Examples) != 1 || got.Examples[0] != "www.slackware.com" {
		t.Fatalf("examples = %v, want [www.slackware.com]", got.Examples)
	}
}

func TestSuggestNetworkSkipsAlreadyAllowed(t *testing.T) {
	svc := New()
	now := time.Now().UTC()
	result, err := svc.Suggest(SuggestRequest{
		AgentName:    "hackerman",
		Since:        now.Add(-24 * time.Hour),
		NetworkScope: "host",
		Records: []audit.Record{
			{
				Timestamp:    now.Add(-2 * time.Hour),
				Agent:        "hackerman",
				Action:       "http:Request",
				Resource:     "www.slackware.com",
				Decision:     "deny",
				DecisionPath: "policy",
				DenialReason: "No policy permits hackerman to reach www.slackware.com",
			},
		},
		ActivePolicies: []PolicyEntry{
			{Effect: "allow", Action: "http:Request", Resource: "slackware.com"},
		},
	})
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if len(result.Network) != 0 {
		t.Fatalf("network suggestions = %d, want 0", len(result.Network))
	}
}

func TestSuggestFilesystemRespectsCoverage(t *testing.T) {
	svc := New()
	now := time.Now().UTC()
	result, err := svc.Suggest(SuggestRequest{
		AgentName:    "hackerman",
		Since:        now.Add(-24 * time.Hour),
		NetworkScope: "host",
		Agent: agent.Agent{
			Volumes: []string{"/tmp:/var/log:rw"},
		},
		Records: []audit.Record{
			{
				Timestamp:    now.Add(-2 * time.Hour),
				Agent:        "hackerman",
				Action:       "file:UpdateSet",
				Resource:     "/opt/app",
				Decision:     "permit",
				DecisionPath: "activity_file",
				Context: map[string]any{
					"files": []string{"main.go", "go.mod"},
				},
			},
			{
				Timestamp:    now.Add(-90 * time.Minute),
				Agent:        "hackerman",
				Action:       "fs:WriteFile",
				Resource:     "/var/log/tool.log",
				Decision:     "deny",
				DecisionPath: "policy",
			},
		},
	})
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if len(result.Filesystem) != 1 {
		t.Fatalf("filesystem suggestions = %d, want 1", len(result.Filesystem))
	}
	got := result.Filesystem[0]
	if got.TargetDir != "/opt/app" {
		t.Fatalf("target = %q, want /opt/app", got.TargetDir)
	}
	if got.Mode != "rw" {
		t.Fatalf("mode = %q, want rw", got.Mode)
	}
	if got.Count != 2 {
		t.Fatalf("count = %d, want 2", got.Count)
	}
	if len(got.Examples) != 2 || !strings.Contains(got.Examples[0], "/opt/app/") {
		t.Fatalf("examples = %v, want two /opt/app file paths", got.Examples)
	}
}

func TestNetworkSuggestionProposal(t *testing.T) {
	svc := New()
	suggestion := NetworkSuggestion{
		Resource: "news.yahoo.com",
		Count:    3,
	}
	allow := svc.NetworkSuggestionProposal("hackerman", suggestion, "allow")
	if !strings.Contains(allow.Cedar, "permit(") {
		t.Fatalf("allow cedar missing permit:\n%s", allow.Cedar)
	}
	if allow.Filename != "hackerman-http-news-yahoo-com.cedar" {
		t.Fatalf("allow filename = %q", allow.Filename)
	}
	deny := svc.NetworkSuggestionProposal("hackerman", suggestion, "deny")
	if !strings.Contains(deny.Cedar, "forbid(") {
		t.Fatalf("deny cedar missing forbid:\n%s", deny.Cedar)
	}
	if deny.Filename != "hackerman-http-news-yahoo-com-forbid.cedar" {
		t.Fatalf("deny filename = %q", deny.Filename)
	}
}
