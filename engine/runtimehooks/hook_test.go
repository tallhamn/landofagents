package runtimehooks

import "testing"

func TestForRuntime_NoHook(t *testing.T) {
	hook := ForRuntime("custom-runtime")
	out, err := hook.Prepare(PrepareInput{RuntimeEnv: []string{"FOO", "BAR"}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(out.RuntimeEnv) != 2 || out.RuntimeEnv[0] != "FOO" || out.RuntimeEnv[1] != "BAR" {
		t.Fatalf("RuntimeEnv = %v, want passthrough", out.RuntimeEnv)
	}
	if len(hook.ManagedMountTargets()) != 0 {
		t.Fatalf("ManagedMountTargets should be empty")
	}
}

func TestBillingPath(t *testing.T) {
	if got := BillingPath("claude-code", "oauth"); got != "Claude subscription (OAuth)" {
		t.Fatalf("BillingPath claude oauth = %q", got)
	}
	if got := BillingPath("claude-code", "api"); got != "Anthropic API key" {
		t.Fatalf("BillingPath claude api = %q", got)
	}
	if got := BillingPath("unknown", "oauth"); got != "" {
		t.Fatalf("BillingPath unknown = %q, want empty", got)
	}
}
