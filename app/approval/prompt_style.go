package approval

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

func pluralWord(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func truncateLabel(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	rs := []rune(strings.TrimSpace(s))
	if len(rs) <= maxRunes {
		return string(rs)
	}
	if maxRunes == 1 {
		return "…"
	}
	return string(rs[:maxRunes-1]) + "…"
}

var urlLikePattern = regexp.MustCompile(`(?i)\b(?:https?://)?[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/[^\s"')\]]*)?`)

func (p *Prompter) blueURLs(text string) string {
	if text == "" {
		return text
	}
	return urlLikePattern.ReplaceAllStringFunc(text, p.blue)
}

func (p *Prompter) blue(text string) string {
	return p.colorize(text, "34")
}

func (p *Prompter) green(text string) string {
	return p.colorize(text, "32")
}

func (p *Prompter) red(text string) string {
	return p.colorize(text, "31")
}

func (p *Prompter) colorize(text, code string) string {
	if !p.useColor {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (p *Prompter) strictChoice(index, max int) string {
	label := fmt.Sprintf("%d", index)
	if !p.useColor {
		return label
	}
	if max <= 0 {
		return label
	}
	palette10 := []int{46, 82, 118, 154, 190, 220, 214, 208, 202, 196}
	palette6 := []int{46, 118, 190, 214, 202, 196}
	switch max {
	case 9:
		return p.colorize(label, fmt.Sprintf("38;5;%d", palette10[clamp(index, 0, 9)]))
	case 5:
		return p.colorize(label, fmt.Sprintf("38;5;%d", palette6[clamp(index, 0, 5)]))
	default:
		// Generic fallback: green to red.
		pos := float64(clamp(index, 0, max)) / float64(max)
		code := 46
		switch {
		case pos >= 0.9:
			code = 196
		case pos >= 0.8:
			code = 202
		case pos >= 0.7:
			code = 208
		case pos >= 0.6:
			code = 214
		case pos >= 0.5:
			code = 220
		case pos >= 0.4:
			code = 190
		case pos >= 0.3:
			code = 154
		case pos >= 0.2:
			code = 118
		case pos >= 0.1:
			code = 82
		}
		return p.colorize(label, fmt.Sprintf("38;5;%d", code))
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func supportsANSI(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	type fdWriter interface{ Fd() uintptr }
	fw, ok := w.(fdWriter)
	if !ok {
		return false
	}
	fi, err := os.NewFile(fw.Fd(), "").Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
