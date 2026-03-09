package approval

import (
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	ansiReset   = "\033[0m"
	ansiGreen   = "\033[32m"
	ansiBlue    = "\033[34m"
	ansiMagenta = "\033[35m"
	ansiCyan    = "\033[36m"
)

var (
	cedarEntityPattern  = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9_]*::"[^"]*"`)
	cedarKeywordPattern = regexp.MustCompile(`\b(permit|forbid|when|unless)\b`)
	cedarFieldPattern   = regexp.MustCompile(`\b(principal|action|resource|context)\b`)
	cedarBoolPattern    = regexp.MustCompile(`\b(true|false)\b`)
)

// FormatCedarForDisplay returns Cedar text with ANSI highlighting when color is enabled.
// It always returns trimmed text and falls back to plain text on non-TTY outputs.
func FormatCedarForDisplay(cedar string, out io.Writer) string {
	text := strings.TrimSpace(cedar)
	if text == "" {
		return ""
	}
	if !shouldUseColor(out) {
		return text
	}
	return highlightCedar(text)
}

func shouldUseColor(out io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("CLICOLOR") == "0" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") == "1" {
		return true
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}

	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func highlightCedar(text string) string {
	highlighted := text
	highlighted = cedarEntityPattern.ReplaceAllStringFunc(highlighted, func(s string) string {
		return colorize(ansiBlue, s)
	})
	highlighted = cedarKeywordPattern.ReplaceAllStringFunc(highlighted, func(s string) string {
		return colorize(ansiGreen, s)
	})
	highlighted = cedarFieldPattern.ReplaceAllStringFunc(highlighted, func(s string) string {
		return colorize(ansiCyan, s)
	})
	highlighted = cedarBoolPattern.ReplaceAllStringFunc(highlighted, func(s string) string {
		return colorize(ansiMagenta, s)
	})
	return highlighted
}

func colorize(color, s string) string {
	return color + s + ansiReset
}
