package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/secrets"
)

func runSecretGrant(args []string) {
	fs := flag.NewFlagSet("secret grant", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name")
	fs.Parse(args)
	if strings.TrimSpace(*agentName) == "" || fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa secret grant --agent <name> <secret-ref>\n")
		os.Exit(1)
	}
	ref := secrets.NormalizeRef(fs.Arg(0))
	kit := kitDir()

	reg, err := secrets.LoadRegistry(kit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if _, ok := reg.Secrets[ref]; !ok {
		fmt.Fprintf(os.Stderr, "Error: secret %q not defined (create with: loa secret set %s --env <ENV_VAR>)\n", ref, ref)
		os.Exit(1)
	}

	mgr := agent.NewManager(kit)
	if err := mgr.AddAllowedSecret(*agentName, ref); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Granted secret %s to %s\n", ref, *agentName)
}

func runSecretRevoke(args []string) {
	fs := flag.NewFlagSet("secret revoke", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name")
	fs.Parse(args)
	if strings.TrimSpace(*agentName) == "" || fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa secret revoke --agent <name> <secret-ref>\n")
		os.Exit(1)
	}
	ref := secrets.NormalizeRef(fs.Arg(0))
	mgr := agent.NewManager(kitDir())
	if err := mgr.RemoveAllowedSecret(*agentName, ref); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Revoked secret %s from %s\n", ref, *agentName)
}
