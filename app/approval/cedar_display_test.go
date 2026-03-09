package approval

import (
	"bytes"
	"strings"
	"testing"
)

func TestFormatCedarForDisplay_DefaultNoColorOnBuffer(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("CLICOLOR", "")
	t.Setenv("TERM", "xterm-256color")

	rendered := FormatCedarForDisplay(`permit(principal, action, resource);`, &bytes.Buffer{})
	if strings.Contains(rendered, "\x1b[") {
		t.Fatalf("expected plain text, got ANSI escapes: %q", rendered)
	}
}

func TestFormatCedarForDisplay_ForceColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("CLICOLOR", "")
	t.Setenv("TERM", "xterm-256color")

	rendered := FormatCedarForDisplay(`permit(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"api.wrike.com"
);`, &bytes.Buffer{})

	if !strings.Contains(rendered, "\x1b[") {
		t.Fatalf("expected ANSI escapes when FORCE_COLOR is set: %q", rendered)
	}
	if !strings.Contains(rendered, "\x1b[32mpermit\x1b[0m") {
		t.Fatalf("expected keyword highlighting for permit: %q", rendered)
	}
}
