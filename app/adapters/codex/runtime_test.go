package codex

import "testing"

func TestIsRuntime(t *testing.T) {
	if !IsRuntime("codex") {
		t.Fatal("expected codex runtime to match")
	}
	if !IsRuntime(" CODEX ") {
		t.Fatal("expected case/space-insensitive runtime match")
	}
	if IsRuntime("claude-code") {
		t.Fatal("did not expect claude-code to match codex adapter")
	}
}

func TestInlineUnsupportedReason(t *testing.T) {
	reason, unsupported := InlineUnsupportedReason("codex")
	if unsupported {
		t.Fatal("did not expect codex inline to be unsupported")
	}
	if reason != "" {
		t.Fatalf("reason=%q want empty", reason)
	}
}
