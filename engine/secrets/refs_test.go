package secrets

import "testing"

func TestNormalizeRefs(t *testing.T) {
	got := NormalizeRefs([]string{" Telegram.Bot_Token ", "telegram.bot_token", "", "model.openrouter"})
	if len(got) != 2 || got[0] != "model.openrouter" || got[1] != "telegram.bot_token" {
		t.Fatalf("NormalizeRefs=%v", got)
	}
}

func TestMissingAllowedRefs(t *testing.T) {
	missing := MissingAllowedRefs(
		[]string{"telegram.bot_token", "model.openrouter", "model.openrouter"},
		[]string{"telegram.bot_token"},
	)
	if len(missing) != 1 || missing[0] != "model.openrouter" {
		t.Fatalf("MissingAllowedRefs=%v", missing)
	}
}

func TestMissingDefinedRefs(t *testing.T) {
	reg := &Registry{Secrets: map[string]Definition{
		"telegram.bot_token": {Env: "TELEGRAM_BOT_TOKEN"},
	}}
	missing := MissingDefinedRefs(reg, []string{"telegram.bot_token", "model.openrouter"})
	if len(missing) != 1 || missing[0] != "model.openrouter" {
		t.Fatalf("MissingDefinedRefs=%v", missing)
	}
}
