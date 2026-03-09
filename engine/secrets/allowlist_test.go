package secrets

import "testing"

func TestFilterDeclaredEnv_NoAllowlist(t *testing.T) {
	fwd, blocked := FilterDeclaredEnv([]string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}, nil)
	if len(blocked) != 0 {
		t.Fatalf("blocked=%v want empty", blocked)
	}
	if got, want := len(fwd), 2; got != want {
		t.Fatalf("forwarded len=%d want %d (%v)", got, want, fwd)
	}
}

func TestFilterDeclaredEnv_WithAllowlist(t *testing.T) {
	fwd, blocked := FilterDeclaredEnv(
		[]string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"},
		[]string{" openai_api_key ", "OPENROUTER_API_KEY"},
	)
	if got, want := len(fwd), 2; got != want {
		t.Fatalf("forwarded len=%d want %d (%v)", got, want, fwd)
	}
	if got, want := len(blocked), 1; got != want {
		t.Fatalf("blocked len=%d want %d (%v)", got, want, blocked)
	}
	if blocked[0] != "ANTHROPIC_API_KEY" {
		t.Fatalf("blocked[0]=%q want ANTHROPIC_API_KEY", blocked[0])
	}
}

func TestFilterDeclaredEnvStrict_ExplicitEmptyFailsClosed(t *testing.T) {
	fwd, blocked := FilterDeclaredEnvStrict(
		[]string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
		nil,
		true,
	)
	if len(fwd) != 0 {
		t.Fatalf("forwarded=%v want empty", fwd)
	}
	if got, want := len(blocked), 2; got != want {
		t.Fatalf("blocked len=%d want %d (%v)", got, want, blocked)
	}
}
