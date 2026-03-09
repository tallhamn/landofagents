package claudecode

import "testing"

func TestIsRuntime(t *testing.T) {
	if !IsRuntime("claude-code") {
		t.Fatal("expected claude-code to match")
	}
	if !IsRuntime(" Claude-Code ") {
		t.Fatal("expected case/space-insensitive runtime match")
	}
	if IsRuntime("codex") {
		t.Fatal("did not expect codex to match claude-code adapter")
	}
}

func TestInlineUnsupportedReason(t *testing.T) {
	reason, unsupported := InlineUnsupportedReason("claude-code")
	if !unsupported {
		t.Fatal("expected claude-code inline to be unsupported")
	}
	if reason == "" {
		t.Fatal("expected non-empty unsupported reason")
	}

	reason, unsupported = InlineUnsupportedReason("codex")
	if unsupported {
		t.Fatal("did not expect codex to be unsupported by claude-code adapter")
	}
	if reason != "" {
		t.Fatalf("reason=%q want empty", reason)
	}
}

func TestBillingPath(t *testing.T) {
	if got := BillingPath("oauth"); got != "Claude subscription (OAuth)" {
		t.Fatalf("BillingPath oauth=%q", got)
	}
	if got := BillingPath("api"); got != "Anthropic API key" {
		t.Fatalf("BillingPath api=%q", got)
	}
}
