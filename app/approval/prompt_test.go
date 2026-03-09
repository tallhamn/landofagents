package approval

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/netscope"
)

func testProposal() ProposalWithCedar {
	return ProposalWithCedar{
		Description: "goggins can make HTTP requests to api.wrike.com",
		Reasoning:   "Goggins needs Wrike for project management",
		Agent:       "goggins",
		DenialIDs:   []string{"AUD-000042"},
		Cedar: `permit(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"api.wrike.com"
);
`,
		Filename: "goggins-http-wrike.cedar",
	}
}

func testDenials() []audit.Record {
	return []audit.Record{
		{
			ID:       "AUD-000042",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "api.wrike.com",
			Decision: "deny",
		},
	}
}

func testHostOnlyDenials() []audit.Record {
	return []audit.Record{
		{
			ID:       "AUD-000043",
			Agent:    "hackerman",
			Action:   "http:Request",
			Resource: "example.com",
			Decision: "deny",
		},
	}
}

func TestPromptOutputFormat(t *testing.T) {
	// With API key: should show compact network prompt and [D]iscuss
	in := strings.NewReader("1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{APIKey: "test-key", AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved, got %d", result.Decision)
	}

	output := out.String()

	// Check key elements present
	checks := []string{
		"LOA: Permission Request",
		"goggins wants to access",
		"api.wrike.com",
		"Strictness scale: 0 = least restrictive, 9 = most restrictive",
		"Choose [0-9/d]:",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q:\n%s", check, output)
		}
	}

	// Filename should NOT appear in the default prompt display
	if strings.Contains(output, "permissions/goggins-http-wrike.cedar") {
		t.Errorf("filename should not appear in default display:\n%s", output)
	}
	if strings.Contains(output, "Permission Request:") {
		t.Errorf("compact network prompt should not show verbose Permission Request section:\n%s", output)
	}
	if strings.Contains(output, "Reasoning:") {
		t.Errorf("compact network prompt should not show reasoning line:\n%s", output)
	}

	// Timestamp should appear in [HH:MM:SS] format
	if !regexp.MustCompile(`\[\d{2}:\d{2}:\d{2}\]`).MatchString(output) {
		t.Errorf("output missing timestamp in [HH:MM:SS] format:\n%s", output)
	}
}

func TestPromptOutputFormat_NoAPIKey(t *testing.T) {
	in := strings.NewReader("1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved, got %d", result.Decision)
	}

	output := out.String()

	// [D]iscuss should NOT be present
	if strings.Contains(output, "[D]iscuss") {
		t.Errorf("[D]iscuss should not appear without API key:\n%s", output)
	}
	// Numeric prompt should be present
	if !strings.Contains(output, "Choose [0-9]:") {
		t.Errorf("missing numeric prompt:\n%s", output)
	}
}

func TestPromptApproveAgentOnly(t *testing.T) {
	in := strings.NewReader("3\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved, got %d", result.Decision)
	}
	if result.Scope != AgentOnly {
		t.Errorf("expected AgentOnly, got %d", result.Scope)
	}
	if result.NetworkScope != NetworkScopeHost {
		t.Errorf("expected NetworkScopeHost, got %d", result.NetworkScope)
	}
	if result.Effect != PolicyPermit {
		t.Errorf("expected PolicyPermit, got %d", result.Effect)
	}
}

func TestPromptApproveAllAgents(t *testing.T) {
	in := strings.NewReader("1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "hackerman"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved, got %d", result.Decision)
	}
	if result.Scope != AllAgents {
		t.Errorf("expected AllAgents, got %d", result.Scope)
	}
	if result.NetworkScope != NetworkScopeHost {
		t.Errorf("expected NetworkScopeHost, got %d", result.NetworkScope)
	}
	if result.Effect != PolicyPermit {
		t.Errorf("expected PolicyPermit, got %d", result.Effect)
	}
}

func TestPromptBlockedOnce(t *testing.T) {
	in := strings.NewReader("5\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != BlockedOnce {
		t.Errorf("expected BlockedOnce, got %d", result.Decision)
	}
}

func TestPromptAllowedOnce(t *testing.T) {
	in := strings.NewReader("4\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != AllowedOnce {
		t.Errorf("expected AllowedOnce, got %d", result.Decision)
	}
}

func TestPromptBlockAllAgentsDomain(t *testing.T) {
	in := strings.NewReader("9\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved, got %d", result.Decision)
	}
	if result.Scope != AllAgents || result.NetworkScope != NetworkScopeDomain || result.Effect != PolicyForbid {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestPromptInvalidThenValid(t *testing.T) {
	in := strings.NewReader("x\nz\n1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved after retries, got %d", result.Decision)
	}

	output := out.String()
	// Should have prompted multiple times
	if strings.Count(output, "Choose [0-9]:") < 2 {
		t.Errorf("expected re-prompt on invalid input, got:\n%s", output)
	}
	if !strings.Contains(output, "Invalid input") {
		t.Errorf("expected invalid input message, got:\n%s", output)
	}
}

func TestPromptDiscuss(t *testing.T) {
	// "d" triggers discuss, reads question, then LLM call will fail (no real key),
	// then re-prompts, then "0"
	in := strings.NewReader("d\nwhat is this?\n1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{APIKey: "test-key", AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved, got %d", result.Decision)
	}

	output := out.String()
	// Should show "Question:" prompt
	if !strings.Contains(output, "Question:") {
		t.Errorf("expected Question: prompt:\n%s", output)
	}
	// Should show discuss error (bad API key) and re-prompt
	if !strings.Contains(output, "Discuss error:") {
		t.Errorf("expected discuss error with fake key:\n%s", output)
	}
	// Should re-prompt after discuss
	if strings.Count(output, "Choose [0-9/d]:") < 2 {
		t.Errorf("expected re-prompt after discuss:\n%s", output)
	}
}

func TestPromptHostOnlyNetworkMenu(t *testing.T) {
	in := strings.NewReader("0\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "hackerman"})

	result, err := p.ShowAndAsk(testProposal(), testHostOnlyDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Fatalf("expected Approved, got %d", result.Decision)
	}
	if result.Scope != AllAgents || result.NetworkScope != NetworkScopeHost || result.Effect != PolicyPermit {
		t.Fatalf("unexpected result: %+v", result)
	}

	output := out.String()
	if !strings.Contains(output, "Broad approval unavailable") {
		t.Fatalf("expected host-only hint in output:\n%s", output)
	}
	if !strings.Contains(output, "Choose [0-5]:") {
		t.Fatalf("expected host-only choice range in output:\n%s", output)
	}
	if strings.Contains(output, "domain ·") {
		t.Fatalf("did not expect domain options in host-only menu:\n%s", output)
	}
}

func TestRegistrableDomainForScope_FallbackParent(t *testing.T) {
	if got := netscope.EffectiveDomain("raw.githubusercontent.com"); got != "githubusercontent.com" {
		t.Fatalf("EffectiveDomain(raw.githubusercontent.com)=%q want githubusercontent.com", got)
	}
	if got := netscope.EffectiveDomain("example.com"); got != "example.com" {
		t.Fatalf("EffectiveDomain(example.com)=%q want example.com", got)
	}
}

func TestPromptDiscuss_NoAPIKey(t *testing.T) {
	// Without API key, "d" should be treated as invalid input
	in := strings.NewReader("d\n1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Errorf("expected Approved, got %d", result.Decision)
	}

	output := out.String()
	if !strings.Contains(output, "Invalid input") {
		t.Errorf("expected invalid input for 'd' without API key:\n%s", output)
	}
}

func TestPromptNetworkScope_Domain(t *testing.T) {
	in := strings.NewReader("2\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Fatalf("expected Approved, got %d", result.Decision)
	}
	if result.NetworkScope != NetworkScopeDomain {
		t.Fatalf("expected NetworkScopeDomain, got %d", result.NetworkScope)
	}
	if result.Effect != PolicyPermit {
		t.Fatalf("expected PolicyPermit, got %d", result.Effect)
	}
	if !strings.Contains(out.String(), "*.wrike.com") {
		t.Fatalf("missing domain wildcard example:\n%s", out.String())
	}
}

func TestPromptNetworkScope_SkippedForNonHTTP(t *testing.T) {
	proposal := testProposal()
	denials := []audit.Record{
		{
			ID:       "AUD-100",
			Agent:    "goggins",
			Action:   "fs:Write",
			Resource: "/workspace/main.go",
			Decision: "deny",
		},
	}

	in := strings.NewReader("a\n1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(proposal, denials)
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.NetworkScope != NetworkScopeHost {
		t.Fatalf("expected default NetworkScopeHost, got %d", result.NetworkScope)
	}
	if strings.Contains(out.String(), "Strictness scale: 0 = least restrictive") {
		t.Fatalf("network scope prompt should not appear for non-http denials:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Hint: if this path should be accessible") {
		t.Fatalf("expected filesystem hint for fs denial:\n%s", out.String())
	}
}

func TestPromptNetworkScope_TruncatesLongAgentName(t *testing.T) {
	proposal := testProposal()
	proposal.Agent = "CARL JONAS MARCUS TALLHAMN THE THIRD"
	in := strings.NewReader("1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: proposal.Agent})

	if _, err := p.ShowAndAsk(proposal, testDenials()); err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "CARL JONAS MARCUS TALLH…") {
		t.Fatalf("expected truncated agent label in options, got:\n%s", got)
	}
}

func TestPromptNetworkInput_BracketedPasteZero(t *testing.T) {
	in := strings.NewReader("\x1b[200~0\x1b[201~\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved || result.Scope != AllAgents || result.NetworkScope != NetworkScopeDomain || result.Effect != PolicyPermit {
		t.Fatalf("unexpected result for bracketed paste zero: %+v", result)
	}
	if strings.Contains(out.String(), "Invalid input") {
		t.Fatalf("did not expect invalid input for bracketed paste sequence:\n%s", out.String())
	}
}

func TestPromptNetworkInput_OptionOneAcceptedImmediately(t *testing.T) {
	in := strings.NewReader("1\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{APIKey: "test-key", AgentName: "hackerman"})

	result, err := p.ShowAndAsk(testProposal(), testDenials())
	if err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	if result.Decision != Approved {
		t.Fatalf("expected Approved, got %d", result.Decision)
	}
	if result.Scope != AllAgents {
		t.Fatalf("expected AllAgents, got %d", result.Scope)
	}
	if result.NetworkScope != NetworkScopeHost {
		t.Fatalf("expected NetworkScopeHost, got %d", result.NetworkScope)
	}
	if result.Effect != PolicyPermit {
		t.Fatalf("expected PolicyPermit, got %d", result.Effect)
	}
	if strings.Contains(out.String(), "Invalid input") {
		t.Fatalf("unexpected invalid input while selecting option 1:\n%s", out.String())
	}
}

func TestPromptNetworkMenuSnapshot_Domain(t *testing.T) {
	proposal := testProposal()
	denials := []audit.Record{{
		ID:        "AUD-200",
		Agent:     "goggins",
		Action:    "http:Request",
		Resource:  "api.wrike.com",
		Decision:  "deny",
		Timestamp: time.Date(2026, 3, 1, 11, 22, 33, 0, time.UTC),
	}}
	in := strings.NewReader("4\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "goggins"})
	if _, err := p.ShowAndAsk(proposal, denials); err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	want := `Strictness scale: 0 = least restrictive, 9 = most restrictive
0) all agents allowed *.wrike.com
1) all agents allowed api.wrike.com
2) goggins allowed *.wrike.com
3) goggins allowed api.wrike.com
4) allow once (this request)
5) block once (this request)
6) goggins blocked api.wrike.com
7) goggins blocked *.wrike.com
8) all agents blocked api.wrike.com
9) all agents blocked *.wrike.com

Choose [0-9]:`
	if !strings.Contains(out.String(), want) {
		t.Fatalf("menu snapshot mismatch:\n%s", out.String())
	}
}

func TestPromptNetworkMenuSnapshot_HostOnly(t *testing.T) {
	proposal := testProposal()
	proposal.Agent = "hackerman"
	denials := []audit.Record{{
		ID:        "AUD-201",
		Agent:     "hackerman",
		Action:    "http:Request",
		Resource:  "example.com",
		Decision:  "deny",
		Timestamp: time.Date(2026, 3, 1, 11, 22, 33, 0, time.UTC),
	}}
	in := strings.NewReader("2\n")
	out := &bytes.Buffer{}
	p := NewPrompter(in, out, PrompterOpts{AgentName: "hackerman"})
	if _, err := p.ShowAndAsk(proposal, denials); err != nil {
		t.Fatalf("ShowAndAsk: %v", err)
	}
	want := `ℹ️  Broad approval unavailable: registrable domain is the same as host (example.com)

Strictness scale: 0 = least restrictive, 5 = most restrictive
0) all agents allowed example.com
1) hackerman allowed example.com
2) allow once (this request)
3) block once (this request)
4) hackerman blocked example.com
5) all agents blocked example.com

Choose [0-5]:`
	if !strings.Contains(out.String(), want) {
		t.Fatalf("host-only menu snapshot mismatch:\n%s", out.String())
	}
}
