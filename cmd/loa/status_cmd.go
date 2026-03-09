package main

import (
	"fmt"
	"os"

	"github.com/marcusmom/land-of-agents/engine/agent"
)

func runStatus(args []string) {
	mgr := agent.NewManager(kitDir())

	if len(args) > 0 {
		name := args[0]
		a, err := mgr.Get(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Agent: %s\n", a.Name)
		fmt.Printf("  Runtime: %s\n", a.Runtime)
		fmt.Printf("  Scope: %s\n", a.Scope)
		if len(a.Volumes) > 0 {
			fmt.Printf("  Volumes:\n")
			for _, v := range a.Volumes {
				fmt.Printf("    %s\n", v)
			}
		}
		if len(a.RememberedVolumes) > 0 {
			fmt.Printf("  Remembered mounts:\n")
			for _, v := range a.RememberedVolumes {
				fmt.Printf("    %s\n", v)
			}
		}
		if len(a.AllowedEnv) > 0 {
			fmt.Printf("  Allowed env:\n")
			for _, e := range a.AllowedEnv {
				fmt.Printf("    %s\n", e)
			}
		}
		if len(a.AllowedSecrets) > 0 {
			fmt.Printf("  Allowed secrets:\n")
			for _, s := range a.AllowedSecrets {
				fmt.Printf("    %s\n", s)
			}
		}
		return
	}

	agents, err := mgr.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(agents) == 0 {
		fmt.Println("No agents. Create one with: loa agent create <name> --runtime claude-code")
		return
	}

	fmt.Printf("Agents (%d):\n", len(agents))
	for _, a := range agents {
		fmt.Printf("  %-15s  %s\n", a.Name, a.Runtime)
	}
}
