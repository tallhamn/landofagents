package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/agent"
)

func runPolicyEffective(args []string) {
	fs := flag.NewFlagSet("policy effective", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name to inspect")
	fs.Parse(args)
	if strings.TrimSpace(*agentName) == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa policy effective --agent <name>\n")
		os.Exit(1)
	}

	kit := kitDir()
	mgr := agent.NewManager(kit)
	a, err := mgr.Get(*agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	entries, err := loadEffectivePolicyEntries(kit, *agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading effective policy: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🧾 Effective access for %s\n", *agentName)
	fmt.Printf("Policy sources: %s\n\n", filepath.Join(kit, "config", "always-allowed.cedar")+", "+filepath.Join(kit, "policies", "active"))

	allowCount, denyCount, unknownCount := countEffectiveEntryEffects(entries)
	fmt.Printf("Policy summary: %d allow, %d deny", allowCount, denyCount)
	if unknownCount > 0 {
		fmt.Printf(", %d unknown", unknownCount)
	}
	fmt.Printf(" (%d rules)\n", len(entries))

	if len(entries) == 0 {
		fmt.Printf("  (no rules found)\n")
	} else {
		fmt.Printf("Rules:\n")
		for _, e := range entries {
			fmt.Printf("  %-5s %-16s %-35s [%s] %s\n", e.Effect, e.Action, blueURLs(e.Resource), e.Scope, e.Source)
		}
	}

	netAllow, netDeny := collectNetworkEffective(entries)
	fmt.Printf("\nNetwork:\n")
	fmt.Printf("  allow: %s\n", formatCSV(netAllow))
	fmt.Printf("  deny:  %s\n", formatCSV(netDeny))

	fmt.Printf("\nFilesystem mounts:\n")
	printMountCategory("  static", a.Volumes)
	printMountCategory("  remembered", a.RememberedVolumes)
	printPathCategory("  never-mount", a.NeverMountDirs)
}
