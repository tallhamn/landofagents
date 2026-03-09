package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/netscope"
	"github.com/marcusmom/land-of-agents/app/services/loaadvisor"
)

func printNetworkSuggestions(advisor *loaadvisor.Service, agentName, scope string, suggestions []loaadvisor.NetworkSuggestion, limit int, showCedar bool) {
	fmt.Printf("Network suggestions: %d\n", len(suggestions))
	if len(suggestions) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	if len(suggestions) > limit {
		suggestions = suggestions[:limit]
	}
	for i, s := range suggestions {
		fmt.Printf("  %d) %s\n", i+1, blueURLs(s.Resource))
		fmt.Printf("     blocked: %d request%s (last %s)\n", s.Count, pluralSuffix(s.Count), s.LastSeen.Local().Format(time.RFC3339))
		if scope == "host" {
			if broader := netscope.EffectiveDomain(s.Resource); broader != "" && broader != s.Resource {
				fmt.Printf("     broader option: *.%s\n", broader)
			}
		}
		if showCedar {
			prop := advisor.NetworkSuggestionProposal(agentName, s, "allow")
			fmt.Printf("     cedar:\n")
			for _, line := range strings.Split(strings.TrimSuffix(prop.Cedar, "\n"), "\n") {
				fmt.Printf("       %s\n", line)
			}
		}
	}
}

func printFilesystemSuggestions(suggestions []loaadvisor.FilesystemSuggestion, limit int) {
	fmt.Printf("Filesystem suggestions: %d\n", len(suggestions))
	if len(suggestions) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	if len(suggestions) > limit {
		suggestions = suggestions[:limit]
	}
	for i, s := range suggestions {
		examples := append([]string{}, s.Examples...)
		if len(examples) > 3 {
			examples = examples[:3]
		}
		fmt.Printf("  %d) %s %s\n", i+1, strings.ToUpper(s.Mode), s.TargetDir)
		fmt.Printf("     observed: %d event%s (last %s)\n", s.Count, pluralSuffix(s.Count), s.LastSeen.Local().Format(time.RFC3339))
		if len(examples) > 0 {
			fmt.Printf("     evidence files: %s\n", strings.Join(examples, ", "))
		}
	}
}

func gradientMenuLine(index int, label string, fullRamp bool) string {
	prefix := fmt.Sprintf("%d) ", index)
	if !supportsANSIStdout() {
		return prefix + label
	}
	if fullRamp {
		switch index {
		case 0:
			return ansiColor(prefix+label, "32")
		case 1:
			return ansiColor(prefix+label, "93")
		case 2:
			return ansiColor(prefix+label, "38;5;208")
		case 3:
			return ansiColor(prefix+label, "31")
		}
	}
	switch index {
	case 0:
		return ansiColor(prefix+label, "32")
	case 1:
		return ansiColor(prefix+label, "31")
	default:
		return prefix + label
	}
}
