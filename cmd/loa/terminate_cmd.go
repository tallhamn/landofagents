package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/contain"
)

func runTerminate(args []string) {
	agentName, err := parseTerminateAgent(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Usage: loa terminate --agent <name>\n")
		os.Exit(1)
	}

	n, err := contain.TerminateAgentStacks(agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error terminating %s: %v\n", agentName, err)
		os.Exit(1)
	}
	if n == 0 {
		fmt.Printf("No active LOA stacks found for %s.\n", agentName)
		return
	}
	fmt.Printf("Terminated %d LOA stack%s for %s.\n", n, pluralSuffix(n), agentName)
}

func parseTerminateAgent(args []string) (string, error) {
	var positional string
	var agentFlag string
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		switch {
		case strings.HasPrefix(a, "--agent="):
			agentFlag = strings.TrimSpace(strings.TrimPrefix(a, "--agent="))
		case a == "--agent":
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag needs an argument: --agent")
			}
			i++
			agentFlag = strings.TrimSpace(args[i])
		case strings.HasPrefix(a, "-"):
			return "", fmt.Errorf("unknown flag: %s", a)
		case positional == "":
			positional = a
		default:
			// Ignore extra positional args for now.
		}
	}
	agentName := strings.TrimSpace(agentFlag)
	if agentName == "" {
		agentName = positional
	}
	if agentName == "" {
		return "", fmt.Errorf("agent name is required")
	}
	return agentName, nil
}
