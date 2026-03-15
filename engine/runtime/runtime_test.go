package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListEmbedded(t *testing.T) {
	names, err := ListEmbedded()
	if err != nil {
		t.Fatalf("ListEmbedded: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("expected at least one embedded runtime")
	}

	foundClaude := false
	foundOpenClaw := false
	for _, n := range names {
		if n == "claude-code" {
			foundClaude = true
		}
		if n == "openclaw" {
			foundOpenClaw = true
		}
	}
	if !foundClaude {
		t.Errorf("claude-code not in embedded runtimes: %v", names)
	}
	if !foundOpenClaw {
		t.Errorf("openclaw not in embedded runtimes: %v", names)
	}
}

func TestExtractTo(t *testing.T) {
	dir := t.TempDir()

	if err := ExtractTo("claude-code", dir); err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}

	// Check runtime.yml exists
	if _, err := os.Stat(filepath.Join(dir, "claude-code", "runtime.yml")); err != nil {
		t.Errorf("runtime.yml not extracted: %v", err)
	}

	// Check Dockerfile exists
	if _, err := os.Stat(filepath.Join(dir, "claude-code", "Dockerfile")); err != nil {
		t.Errorf("Dockerfile not extracted: %v", err)
	}

	// Check entrypoint.sh exists
	if _, err := os.Stat(filepath.Join(dir, "claude-code", "entrypoint.sh")); err != nil {
		t.Errorf("entrypoint.sh not extracted: %v", err)
	}

	// Check proxy-setup.js exists
	if _, err := os.Stat(filepath.Join(dir, "claude-code", "proxy-setup.js")); err != nil {
		t.Errorf("proxy-setup.js not extracted: %v", err)
	}

	// Check command-guard.sh exists
	if _, err := os.Stat(filepath.Join(dir, "claude-code", "command-guard.sh")); err != nil {
		t.Errorf("command-guard.sh not extracted: %v", err)
	}

	// Check command-mappings.yml exists
	if _, err := os.Stat(filepath.Join(dir, "claude-code", "command-mappings.yml")); err != nil {
		t.Errorf("command-mappings.yml not extracted: %v", err)
	}
}

func TestExtractToSkipsExisting(t *testing.T) {
	dir := t.TempDir()

	// Create target dir with custom content
	target := filepath.Join(dir, "claude-code")
	os.MkdirAll(target, 0755)
	os.WriteFile(filepath.Join(target, "custom.txt"), []byte("custom"), 0644)

	if err := ExtractTo("claude-code", dir); err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}

	// Custom file should still be there
	if _, err := os.Stat(filepath.Join(target, "custom.txt")); err != nil {
		t.Error("custom.txt was overwritten")
	}

	// runtime.yml should NOT have been extracted (dir already existed)
	if _, err := os.Stat(filepath.Join(target, "runtime.yml")); err == nil {
		t.Error("runtime.yml should not have been extracted into existing dir")
	}
}

func TestLoad(t *testing.T) {
	// Extract to temp, then load from disk
	dir := t.TempDir()
	if err := ExtractTo("claude-code", dir); err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}

	rt, err := Load(filepath.Join(dir, "claude-code"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if rt.Name != "claude-code" {
		t.Errorf("name: got %q, want %q", rt.Name, "claude-code")
	}
	if rt.Hook != "claude-code" {
		t.Errorf("hook: got %q, want %q", rt.Hook, "claude-code")
	}

	if rt.Build == nil {
		t.Fatal("expected Build to be set")
	}
	if rt.Build.Dockerfile != "Dockerfile" {
		t.Errorf("dockerfile: got %q", rt.Build.Dockerfile)
	}

	if rt.Image != "" {
		t.Errorf("image should be empty for build runtime, got %q", rt.Image)
	}

	if len(rt.Env) == 0 {
		t.Fatal("expected env vars")
	}
	foundOAuth := false
	for _, env := range rt.Env {
		if env == "CLAUDE_CODE_OAUTH_TOKEN" {
			foundOAuth = true
		}
	}
	if !foundOAuth {
		t.Error("runtime env missing CLAUDE_CODE_OAUTH_TOKEN")
	}

	if rt.BaseCedar == "" {
		t.Error("base_cedar is empty")
	}
	if len(rt.BaseCedarBlocks) < 4 {
		t.Fatalf("expected runtime-specific base_cedar_blocks, got %d", len(rt.BaseCedarBlocks))
	}
}

func TestRenderBaseCedar_ClaudeByAuthMode(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractTo("claude-code", dir); err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}
	rt, err := Load(filepath.Join(dir, "claude-code"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := rt.RenderBaseCedar("oauth")
	if err != nil {
		t.Fatalf("RenderBaseCedar(oauth): %v", err)
	}
	for _, domain := range []string{"platform.claude.com", "claude.ai"} {
		if !strings.Contains(got, domain) {
			t.Fatalf("oauth baseline missing %s:\n%s", domain, got)
		}
	}
	if strings.Contains(got, "api.anthropic.com") {
		t.Fatalf("oauth baseline should not include api.anthropic.com:\n%s", got)
	}

	got, err = rt.RenderBaseCedar("api")
	if err != nil {
		t.Fatalf("RenderBaseCedar(api): %v", err)
	}
	if !strings.Contains(got, "api.anthropic.com") {
		t.Fatalf("api baseline missing anthropic endpoint:\n%s", got)
	}
	if strings.Contains(got, "platform.claude.com") {
		t.Fatalf("api baseline should not include oauth endpoint:\n%s", got)
	}
}

func TestRenderBaseCedar_FoundryUsesEndpointTemplate(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractTo("claude-code", dir); err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}
	rt, err := Load(filepath.Join(dir, "claude-code"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	t.Setenv("AZURE_OPENAI_ENDPOINT", "https://my-resource.openai.azure.com/v1")
	got, err := rt.RenderBaseCedar("foundry")
	if err != nil {
		t.Fatalf("RenderBaseCedar(foundry): %v", err)
	}
	if !strings.Contains(got, `Resource::"azure.com"`) {
		t.Fatalf("foundry baseline missing rendered endpoint domain:\n%s", got)
	}
}

func TestRenderBaseCedar_OpenClawIncludesOnlyPresentProviderEnv(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractTo("openclaw", dir); err != nil {
		t.Fatalf("ExtractTo(openclaw): %v", err)
	}
	rt, err := Load(filepath.Join(dir, "openclaw"))
	if err != nil {
		t.Fatalf("Load(openclaw): %v", err)
	}

	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENROUTER_API_KEY", "")

	got, err := rt.RenderBaseCedar("")
	if err != nil {
		t.Fatalf("RenderBaseCedar(openclaw): %v", err)
	}
	if !strings.Contains(got, "api.openai.com") {
		t.Fatalf("openclaw baseline missing openai endpoint:\n%s", got)
	}
	for _, domain := range []string{"api.telegram.org", "api.anthropic.com", "openrouter.ai"} {
		if strings.Contains(got, domain) {
			t.Fatalf("openclaw baseline should not include %s without env:\n%s", domain, got)
		}
	}
}

func TestExtractTo_OpenClaw(t *testing.T) {
	dir := t.TempDir()

	if err := ExtractTo("openclaw", dir); err != nil {
		t.Fatalf("ExtractTo(openclaw): %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "openclaw", "runtime.yml")); err != nil {
		t.Errorf("openclaw runtime.yml not extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "openclaw", "Dockerfile")); err == nil {
		t.Errorf("openclaw should be image-based; unexpected Dockerfile extracted")
	}
}

func TestLoadOpenClaw(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractTo("openclaw", dir); err != nil {
		t.Fatalf("ExtractTo(openclaw): %v", err)
	}

	rt, err := Load(filepath.Join(dir, "openclaw"))
	if err != nil {
		t.Fatalf("Load(openclaw): %v", err)
	}
	if rt.Name != "openclaw" {
		t.Fatalf("name: got %q, want openclaw", rt.Name)
	}
	if rt.Hook != "openclaw" {
		t.Fatalf("hook: got %q, want openclaw", rt.Hook)
	}
	if rt.Build != nil {
		t.Fatal("openclaw should be image-based (build must be nil)")
	}
	if rt.Image != "ghcr.io/openclaw/openclaw:latest" {
		t.Fatalf("image: got %q, want ghcr.io/openclaw/openclaw:latest", rt.Image)
	}
	if len(rt.Env) == 0 {
		t.Fatal("openclaw env should declare provider token vars")
	}
	if !strings.Contains(rt.BaseCedar, "OpenClaw baseline") {
		t.Fatalf("expected explanatory base_cedar comment, got: %q", rt.BaseCedar)
	}
}

func TestLoad_DefaultsHookToRuntimeName(t *testing.T) {
	dir := t.TempDir()
	rtDir := filepath.Join(dir, "custom")
	if err := os.MkdirAll(rtDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rtDir, "runtime.yml"), []byte(`image: alpine:latest`), 0644); err != nil {
		t.Fatalf("write runtime.yml: %v", err)
	}

	rt, err := Load(rtDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rt.Hook != "custom" {
		t.Fatalf("Hook = %q, want custom", rt.Hook)
	}
}
