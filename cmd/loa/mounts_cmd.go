package main

import (
	"fmt"
	"os"

	"github.com/marcusmom/land-of-agents/engine/agent"
)

func runMounts(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa mounts <agent> [list|remove <index>]\n")
		os.Exit(1)
	}
	agentName := args[0]
	action := "list"
	if len(args) >= 2 {
		action = args[1]
	}

	mgr := agent.NewManager(kitDir())
	a, err := mgr.Get(agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	switch action {
	case "list":
		printRememberedMounts(agentName, a.RememberedVolumes)
	case "remove":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: loa mounts %s remove <index>\n", agentName)
			os.Exit(1)
		}
		var idx int
		if _, err := fmt.Sscanf(args[2], "%d", &idx); err != nil || idx < 1 || idx > len(a.RememberedVolumes) {
			fmt.Fprintf(os.Stderr, "Error: invalid index %q\n", args[2])
			os.Exit(1)
		}
		volume := a.RememberedVolumes[idx-1]
		if err := mgr.RemoveRememberedVolume(agentName, volume); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Removed remembered mount #%d for %s: %s\n", idx, agentName, volume)
	default:
		fmt.Fprintf(os.Stderr, "Usage: loa mounts <agent> [list|remove <index>]\n")
		os.Exit(1)
	}
}

func printRememberedMounts(agentName string, volumes []string) {
	fmt.Printf("Remembered mounts for %s (%d):\n", agentName, len(volumes))
	if len(volumes) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	fmt.Printf("  #   %-45s %-28s %s\n", "Host", "Container", "Mode")
	for i, v := range volumes {
		src, dst, mode := parseMountSpec(v)
		fmt.Printf("  %-3d %-45s %-28s %s\n", i+1, src, dst, mode)
	}
}
