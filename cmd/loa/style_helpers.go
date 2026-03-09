package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/netscope"
)


func indentLines(text, prefix string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}


func printSection(title string) {
	fmt.Println()
	fmt.Println(title)
}

func promptNetworkScope(in io.Reader, out io.Writer, resource string) approval.NetworkScope {
	reader := bufio.NewReader(in)
	host := netscope.NormalizeHost(resource)
	if host == "" {
		host = "this host"
	}
	domain := netscope.EffectiveDomain(host)
	if domain == "" {
		domain = host
	}
	for {
		fmt.Fprintf(out, "Network scope:\n")
		fmt.Fprintf(out, "  [1] Narrow approval (%s only)\n", blueURLs(host))
		fmt.Fprintf(out, "  [2] Broad approval  (all %s hosts)\n", blueURLs(domain))
		fmt.Fprintf(out, "Choose scope [1/2]: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return approval.NetworkScopeHost
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "1", "h", "n", "narrow":
			return approval.NetworkScopeHost
		case "2", "d", "a", "b", "broad":
			return approval.NetworkScopeDomain
		default:
			fmt.Fprintf(out, "Invalid input. Enter 1 or 2.\n")
		}
	}
}

var urlTokenPattern = regexp.MustCompile(`(?i)\b(?:https?://)?[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/[^\s"')\]]*)?`)

func blueURLs(text string) string {
	return urlTokenPattern.ReplaceAllStringFunc(text, func(token string) string {
		return ansiColor(token, "34")
	})
}

func ansiColor(text, code string) string {
	if text == "" || !supportsANSIStdout() {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func supportsANSIStdout() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
