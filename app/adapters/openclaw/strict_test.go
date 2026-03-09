package openclaw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsEnabled(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"1", true},
		{"true", true},
		{"yes", true},
		{"on", true},
	}
	for _, tt := range tests {
		t.Setenv(EnvRequireWorkerAPI, tt.val)
		if got := IsEnabled(); got != tt.want {
			t.Fatalf("IsEnabled(%q)=%v want %v", tt.val, got, tt.want)
		}
	}
}

func TestValidateRunPreflight_StrictOpenClaw(t *testing.T) {
	t.Setenv(EnvRequireWorkerAPI, "1")
	t.Setenv(EnvWorkerBackend, "loa")

	launcher := filepath.Join(t.TempDir(), "launcher.sh")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write launcher: %v", err)
	}
	t.Setenv(EnvWorkerLauncher, launcher)

	if err := ValidateRunPreflight("openclaw"); err != nil {
		t.Fatalf("ValidateRunPreflight returned error: %v", err)
	}
}

func TestValidateRunPreflight_NonOpenClawSkipsStrictChecks(t *testing.T) {
	t.Setenv(EnvRequireWorkerAPI, "1")
	t.Setenv(EnvWorkerBackend, "")
	t.Setenv(EnvWorkerLauncher, "")
	if err := ValidateRunPreflight("claude-code"); err != nil {
		t.Fatalf("expected no error for non-openclaw runtime, got %v", err)
	}
}

func TestValidateStrictWorkerLaunch(t *testing.T) {
	t.Setenv(EnvRequireWorkerAPI, "1")
	if err := ValidateStrictWorkerLaunch("openclaw", []string{"/srv/loa/resources:/clawkeeper:rw"}, "enforce", "existing-active", "least", "openclaw-gateway"); err != nil {
		t.Fatalf("strict launch should pass: %v", err)
	}
	if err := ValidateStrictWorkerLaunch("openclaw", []string{"/var/run/docker.sock:/var/run/docker.sock"}, "enforce", "existing-active", "least", "openclaw-gateway"); err == nil {
		t.Fatal("expected docker socket rejection")
	}
	if err := ValidateStrictWorkerLaunch("openclaw", nil, "log", "existing-active", "least", "openclaw-gateway"); err == nil {
		t.Fatal("expected mode rejection")
	}
	if err := ValidateStrictWorkerLaunch("openclaw", nil, "enforce", "bootstrap-all", "least", "openclaw-gateway"); err == nil {
		t.Fatal("expected scope rejection")
	}
	if err := ValidateStrictWorkerLaunch("openclaw", nil, "enforce", "existing-active", "broad", "openclaw-gateway"); err == nil {
		t.Fatal("expected exposure rejection")
	}
	if err := ValidateStrictWorkerLaunch("openclaw", nil, "enforce", "existing-active", "least", "not-gateway"); err == nil {
		t.Fatal("expected source label rejection")
	}
}

func TestForbiddenVolumeSources(t *testing.T) {
	in := []string{
		"/var/run/docker.sock:/var/run/docker.sock",
		"/srv/loa/resources:/clawkeeper:rw",
		"/run/docker.sock:/run/docker.sock",
		"/var/run/docker.sock:/docker.sock:ro",
	}
	got := ForbiddenVolumeSources(in)
	if len(got) != 2 {
		t.Fatalf("forbidden sources=%v want 2 entries", got)
	}
	if got[0] != "/run/docker.sock" || got[1] != "/var/run/docker.sock" {
		t.Fatalf("unexpected forbidden sources ordering/content: %v", got)
	}
}

func TestValidateStrictWorkerLaunchSkipsNonStrictRuntime(t *testing.T) {
	t.Setenv(EnvRequireWorkerAPI, "1")
	if err := ValidateStrictWorkerLaunch("claude-code", nil, "log", "bootstrap-all", "broad", "anything"); err != nil {
		t.Fatalf("non-openclaw runtime should skip strict validation, got %v", err)
	}
	t.Setenv(EnvRequireWorkerAPI, "0")
	if err := ValidateStrictWorkerLaunch("openclaw", nil, "log", "bootstrap-all", "broad", "anything"); err != nil {
		t.Fatalf("strict disabled should skip validation, got %v", err)
	}
}

func TestValidateStrictWorkerLaunchErrorMessages(t *testing.T) {
	t.Setenv(EnvRequireWorkerAPI, "1")
	err := ValidateStrictWorkerLaunch("openclaw", nil, "log", "existing-active", "least", "openclaw-gateway")
	if err == nil || !strings.Contains(err.Error(), "network_profile.mode=enforce") {
		t.Fatalf("unexpected mode error: %v", err)
	}
}
