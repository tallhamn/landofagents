package runtimehooks

import (
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

func TestClaudeCodeHookPrepare(t *testing.T) {
	hook := claudeCodeHook{}
	workspaceDir := t.TempDir()
	t.Setenv("LOA_CLAUDE_AUTH_MODE", "api")

	out, err := hook.Prepare(PrepareInput{
		WorkspaceDir: workspaceDir,
		RuntimeEnv: []string{
			"CLAUDE_CODE_OAUTH_TOKEN",
			"ANTHROPIC_API_KEY",
			"AWS_ACCESS_KEY_ID",
		},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if out.AuthMode != "api" {
		t.Fatalf("AuthMode = %q, want api", out.AuthMode)
	}
	if len(out.RuntimeEnv) != 1 || out.RuntimeEnv[0] != "ANTHROPIC_API_KEY" {
		t.Fatalf("RuntimeEnv = %v, want [ANTHROPIC_API_KEY]", out.RuntimeEnv)
	}
	if len(out.AgentEnv) != 2 || out.AgentEnv[0] != "CLAUDE_CONFIG_DIR=/home/node/.claude" || out.AgentEnv[1] != "LOA_COMMAND_POLICY_MODE=discover" {
		t.Fatalf("AgentEnv = %v", out.AgentEnv)
	}
	if len(out.AgentVolumes) != 1 {
		t.Fatalf("AgentVolumes = %v", out.AgentVolumes)
	}
	if !strings.HasSuffix(out.AgentVolumes[0], ":/home/node/.claude") {
		t.Fatalf("AgentVolumes[0] = %q", out.AgentVolumes[0])
	}
	if _, err := os.Stat(filepath.Join(workspaceDir, ".claude")); err != nil {
		t.Fatalf("expected .claude dir to be created: %v", err)
	}
}

func TestResolveCommandPolicyMode(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("LOA_COMMAND_POLICY_MODE", "")
		if got := resolveCommandPolicyMode(); got != "discover" {
			t.Fatalf("got %q, want discover", got)
		}
	})
	t.Run("legacy enforce falls back", func(t *testing.T) {
		t.Setenv("LOA_COMMAND_POLICY_MODE", "enforce")
		if got := resolveCommandPolicyMode(); got != "discover" {
			t.Fatalf("got %q, want discover", got)
		}
	})
	t.Run("off", func(t *testing.T) {
		t.Setenv("LOA_COMMAND_POLICY_MODE", "off")
		if got := resolveCommandPolicyMode(); got != "off" {
			t.Fatalf("got %q, want off", got)
		}
	})
}

func TestClaudeCodeHookManagedMountTargets(t *testing.T) {
	hook := claudeCodeHook{}
	targets := hook.ManagedMountTargets()
	if len(targets) != 1 || targets[0] != "/home/node/.claude" {
		t.Fatalf("ManagedMountTargets = %v", targets)
	}
}

func TestSeedClaudeAuth_SkipsWhenExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude-missing"))
	// On developer machines with real Claude credentials, seedClaudeAuth may
	// intentionally refresh from host. This test only verifies fallback behavior
	// when host creds are unavailable.
	if _, err := readHostClaudeCredentials(); err == nil {
		t.Skip("host Claude credentials available; skip fallback-only assertion")
	}

	configDir := t.TempDir()

	// Pre-create the credentials file
	credPath := filepath.Join(configDir, ".credentials.json")
	_ = os.WriteFile(credPath, []byte(`{"existing": true}`), 0600)

	// Should skip without error
	if err := seedClaudeAuth(configDir); err != nil {
		t.Fatalf("seedClaudeAuth should skip when credentials exist: %v", err)
	}

	// Content should be unchanged
	data, _ := os.ReadFile(credPath)
	if string(data) != `{"existing": true}` {
		t.Error("seedClaudeAuth overwrote existing credentials")
	}
}

func TestSeedClaudeAuth_RefreshesFromHostWhenChanged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hostDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}
	hostCredPath := filepath.Join(hostDir, ".credentials.json")
	hostData := []byte(`{"accessToken":"fresh-token"}`)
	if err := os.WriteFile(hostCredPath, hostData, 0600); err != nil {
		t.Fatalf("write host credentials: %v", err)
	}

	configDir := t.TempDir()
	credPath := filepath.Join(configDir, ".credentials.json")
	if err := os.WriteFile(credPath, []byte(`{"accessToken":"stale-token"}`), 0600); err != nil {
		t.Fatalf("write existing credentials: %v", err)
	}

	if err := seedClaudeAuth(configDir); err != nil {
		t.Fatalf("seedClaudeAuth should refresh from host: %v", err)
	}

	got, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("read refreshed credentials: %v", err)
	}
	if string(got) != string(hostData) {
		t.Fatalf("expected refreshed credentials %q, got %q", string(hostData), string(got))
	}
}

func TestSeedClaudeAuth_FromKeychain(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	hasKeychainCreds := false
	for _, service := range claudeKeychainServiceNames() {
		if _, err := exec.Command("security", "find-generic-password", "-s", service, "-w").Output(); err == nil {
			hasKeychainCreds = true
			break
		}
	}
	if !hasKeychainCreds {
		t.Skip("no Claude Code credentials in Keychain")
	}

	configDir := t.TempDir()
	if err := seedClaudeAuth(configDir); err != nil {
		t.Fatalf("seedClaudeAuth: %v", err)
	}

	credPath := filepath.Join(configDir, ".credentials.json")
	data, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("credentials file not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("credentials file is empty")
	}
	if !strings.Contains(string(data), "accessToken") {
		t.Error("credentials file doesn't contain accessToken")
	}

	info, _ := os.Stat(credPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestSeedClaudeConfig_CreatesMinimalConfig(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	seedClaudeConfig(configDir)

	configPath := filepath.Join(configDir, ".claude.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if string(data) != `{"bypassPermissionsModeAccepted":true}` {
		t.Errorf("unexpected config content: %s", string(data))
	}

	// Check permissions
	info, _ := os.Stat(configPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestSeedClaudeConfig_SkipsWhenExists(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	// Pre-create the config file
	configPath := filepath.Join(configDir, ".claude.json")
	_ = os.WriteFile(configPath, []byte(`{"custom": true}`), 0600)

	seedClaudeConfig(configDir)

	data, _ := os.ReadFile(configPath)
	if string(data) != `{"custom": true}` {
		t.Error("seedClaudeConfig overwrote existing config")
	}
}

func TestSeedClaudeConfig_CopiesHostConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hostConfig := filepath.Join(home, ".claude.json")
	hostData := []byte(`{"oauthAccount":{"emailAddress":"user@example.com"}}`)
	if err := os.WriteFile(hostConfig, hostData, 0600); err != nil {
		t.Fatalf("write host config: %v", err)
	}

	configDir := t.TempDir()
	seedClaudeConfig(configDir)

	configPath := filepath.Join(configDir, ".claude.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if string(data) != string(hostData) {
		t.Errorf("expected copied host config, got: %s", string(data))
	}
}

func TestResolveClaudeAutoAuthMode(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("AZURE_OPENAI_API_KEY", "")
	t.Setenv("AZURE_OPENAI_ENDPOINT", "")

	if got := resolveClaudeAutoAuthMode(true); got != "oauth" {
		t.Fatalf("hasOAuth=true should force oauth, got %q", got)
	}
	if got := resolveClaudeAutoAuthMode(false); got != "api" {
		t.Fatalf("expected api fallback when only API key set, got %q", got)
	}
}

func TestResolveClaudeAutoAuthMode_ProviderDetection(t *testing.T) {
	t.Run("bedrock", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIA...")
		t.Setenv("AWS_PROFILE", "")
		if got := resolveClaudeAutoAuthMode(false); got != "bedrock" {
			t.Fatalf("expected bedrock, got %q", got)
		}
	})

	t.Run("vertex", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_PROFILE", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/gcp.json")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "")
		if got := resolveClaudeAutoAuthMode(false); got != "vertex" {
			t.Fatalf("expected vertex, got %q", got)
		}
	})

	t.Run("foundry", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_PROFILE", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GOOGLE_CLOUD_PROJECT", "")
		t.Setenv("AZURE_OPENAI_API_KEY", "test")
		t.Setenv("AZURE_OPENAI_ENDPOINT", "")
		if got := resolveClaudeAutoAuthMode(false); got != "foundry" {
			t.Fatalf("expected foundry, got %q", got)
		}
	})
}

func TestFilterClaudeRuntimeEnvVars(t *testing.T) {
	input := []string{
		"CLAUDE_CODE_OAUTH_TOKEN",
		"ANTHROPIC_API_KEY",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"AZURE_OPENAI_API_KEY",
	}

	tests := []struct {
		mode string
		want []string
	}{
		{mode: "oauth", want: []string{"CLAUDE_CODE_OAUTH_TOKEN"}},
		{mode: "api", want: []string{"ANTHROPIC_API_KEY"}},
		{mode: "bedrock", want: []string{"AWS_ACCESS_KEY_ID"}},
		{mode: "vertex", want: []string{"GOOGLE_APPLICATION_CREDENTIALS"}},
		{mode: "foundry", want: []string{"AZURE_OPENAI_API_KEY"}},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got := filterClaudeRuntimeEnvVars(input, tt.mode)
			if len(got) != len(tt.want) {
				t.Fatalf("mode=%s got %v, want %v", tt.mode, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("mode=%s got %v, want %v", tt.mode, got, tt.want)
				}
			}
		})
	}
}

func TestSummarizeClaudeExposure(t *testing.T) {
	t.Setenv("LOA_CLAUDE_AUTH_MODE", "api")
	t.Setenv("LOA_COMMAND_POLICY_MODE", "discover")
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	s := SummarizeClaudeExposure([]string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID"})
	if s.RequestedAuthMode != "api" {
		t.Fatalf("RequestedAuthMode = %q, want api", s.RequestedAuthMode)
	}
	if s.EffectiveAuthMode != "api" {
		t.Fatalf("EffectiveAuthMode = %q, want api", s.EffectiveAuthMode)
	}
	if s.CommandPolicyMode != "discover" {
		t.Fatalf("CommandPolicyMode = %q, want discover", s.CommandPolicyMode)
	}
	if s.BillingPath != "Anthropic API key" {
		t.Fatalf("BillingPath = %q, want Anthropic API key", s.BillingPath)
	}
	if len(s.ForwardedEnv) != 1 || s.ForwardedEnv[0] != "ANTHROPIC_API_KEY" {
		t.Fatalf("ForwardedEnv = %v, want [ANTHROPIC_API_KEY]", s.ForwardedEnv)
	}
	if len(s.PresentEnv) != 1 || s.PresentEnv[0] != "ANTHROPIC_API_KEY" {
		t.Fatalf("PresentEnv = %v, want [ANTHROPIC_API_KEY]", s.PresentEnv)
	}
	if len(s.MissingEnv) != 0 {
		t.Fatalf("MissingEnv = %v, want empty", s.MissingEnv)
	}
}

func TestClaudeBillingPathForMode(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{mode: "oauth", want: "Claude subscription (OAuth)"},
		{mode: "api", want: "Anthropic API key"},
		{mode: "bedrock", want: "AWS Bedrock"},
		{mode: "vertex", want: "Google Vertex AI"},
		{mode: "foundry", want: "Microsoft Foundry/Azure"},
		{mode: "weird", want: "unknown"},
	}
	for _, tt := range tests {
		if got := claudeBillingPathForMode(tt.mode); got != tt.want {
			t.Fatalf("mode=%s got %q, want %q", tt.mode, got, tt.want)
		}
	}
}
