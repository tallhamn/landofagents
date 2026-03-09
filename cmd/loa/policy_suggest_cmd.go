package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/app/services/loaadvisor"
)

func runPolicySuggest(args []string) {
	fs := flag.NewFlagSet("policy suggest", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name to inspect")
	sinceRaw := fs.String("since", "24h", "Only include recent activity (e.g. 24h, 7d, 90m)")
	networkScope := fs.String("network-scope", "host", "Network suggestion scope: host|domain")
	limit := fs.Int("limit", 10, "Maximum suggestions per section")
	interactive := fs.Bool("interactive", isInteractiveTerminal(), "Interactively stage/activate network suggestions")
	showCedar := fs.Bool("show-cedar", false, "Include Cedar snippets in non-interactive output")
	fs.Parse(args)

	if strings.TrimSpace(*agentName) == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa policy suggest --agent <name> [--since 24h] [--network-scope host|domain] [--limit 10]\n")
		os.Exit(1)
	}
	if *networkScope != "host" && *networkScope != "domain" {
		fmt.Fprintf(os.Stderr, "Error: --network-scope must be host or domain\n")
		os.Exit(1)
	}
	if *limit <= 0 {
		*limit = 10
	}

	windowStart, windowLabel, err := parseSuggestWindow(*sinceRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: --since %v\n", err)
		os.Exit(1)
	}

	kit := kitDir()
	mgr := agent.NewManager(kit)
	a, err := mgr.Get(*agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	records, err := loadAuditRecords(kit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading audit records: %v\n", err)
		os.Exit(1)
	}

	entries, err := loadEffectivePolicyEntries(kit, *agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading active policies: %v\n", err)
		os.Exit(1)
	}

	active := make([]loaadvisor.PolicyEntry, 0, len(entries))
	for _, e := range entries {
		active = append(active, loaadvisor.PolicyEntry{
			Effect:   e.Effect,
			Action:   e.Action,
			Resource: e.Resource,
		})
	}
	advisor := loaadvisor.New()
	suggestions, err := advisor.Suggest(loaadvisor.SuggestRequest{
		AgentName:      *agentName,
		Since:          windowStart,
		NetworkScope:   *networkScope,
		Records:        records,
		Agent:          a,
		ActivePolicies: active,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating suggestions: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🧪 Suggestions for %s (%s)\n\n", *agentName, windowLabel)

	printNetworkSuggestions(advisor, *agentName, *networkScope, suggestions.Network, *limit, *showCedar)
	fmt.Println()
	printFilesystemSuggestions(suggestions.Filesystem, *limit)
	if *interactive {
		runPolicySuggestInteractive(advisor, *agentName, kit, suggestions.Network, *limit, *networkScope)
	} else if len(suggestions.Network) > 0 {
		fmt.Println()
		fmt.Printf("Tip: rerun with --interactive to stage/activate network suggestions.\n")
	}
}

func parseSuggestWindow(raw string) (time.Time, string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		raw = "24h"
	}
	if strings.HasSuffix(raw, "d") {
		n := strings.TrimSpace(strings.TrimSuffix(raw, "d"))
		days, err := time.ParseDuration(n + "24h")
		if err != nil {
			return time.Time{}, "", err
		}
		return time.Now().Add(-days), "last " + raw, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return time.Time{}, "", err
	}
	return time.Now().Add(-d), "last " + raw, nil
}
