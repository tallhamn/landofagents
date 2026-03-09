package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistry_SetResolveAndDelete(t *testing.T) {
	r := &Registry{Secrets: map[string]Definition{}}
	if err := r.SetDefinition("telegram.bot_token", "TELEGRAM_BOT_TOKEN", "telegram bot token", []string{RoleGateway}); err != nil {
		t.Fatalf("SetDefinition: %v", err)
	}
	if err := r.SetDefinition("databricks.pat", "DATABRICKS_TOKEN", "db token", []string{RoleWorker}); err != nil {
		t.Fatalf("SetDefinition: %v", err)
	}

	envVars, missing := r.ResolveAllowedEnvFromRefs([]string{"telegram.bot_token", "missing.ref", "DATABRICKS.PAT"})
	if len(envVars) != 2 || envVars[0] != "DATABRICKS_TOKEN" || envVars[1] != "TELEGRAM_BOT_TOKEN" {
		t.Fatalf("resolved env vars = %v", envVars)
	}
	if len(missing) != 1 || missing[0] != "missing.ref" {
		t.Fatalf("missing refs = %v", missing)
	}

	if !r.DeleteDefinition("telegram.bot_token") {
		t.Fatal("expected delete success")
	}
	if r.DeleteDefinition("telegram.bot_token") {
		t.Fatal("expected second delete to fail")
	}
}

func TestDefinitionAllowsRole_DefaultIsGatewayOnly(t *testing.T) {
	def := Definition{Env: "TOKEN"}
	if !DefinitionAllowsRole(def, RoleGateway) {
		t.Fatal("expected gateway role allowed by default")
	}
	if DefinitionAllowsRole(def, RoleWorker) {
		t.Fatal("expected worker role denied by default")
	}
}

func TestRegistry_RefsNotExposedToRole(t *testing.T) {
	r := &Registry{Secrets: map[string]Definition{
		"gateway.only": {Env: "GW", Roles: []string{RoleGateway}},
		"worker.only":  {Env: "WK", Roles: []string{RoleWorker}},
		"both":         {Env: "BOTH", Roles: []string{RoleGateway, RoleWorker}},
	}}
	denied := r.RefsNotExposedToRole([]string{"gateway.only", "worker.only", "both"}, RoleWorker)
	if len(denied) != 1 || denied[0] != "gateway.only" {
		t.Fatalf("denied=%v want [gateway.only]", denied)
	}
}

func TestLoadRegistryRejectsUnsupportedRole(t *testing.T) {
	kit := t.TempDir()
	path := filepath.Join(kit, "config", "secrets.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := []byte(`secrets:
  telegram.bot_token:
    env: TELEGRAM_BOT_TOKEN
    roles: [admin]
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write secrets.yml: %v", err)
	}

	_, err := LoadRegistry(kit)
	if err == nil {
		t.Fatal("expected unsupported role error")
	}
	if !strings.Contains(err.Error(), "unsupported roles") {
		t.Fatalf("unexpected error: %v", err)
	}
}
