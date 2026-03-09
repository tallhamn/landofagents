package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/agent"
)

func maybeOfferCWDMount(mgr *agent.Manager, agentName string, a *agent.Agent) (string, error) {
	if !isInteractiveTerminal() {
		return "", nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", nil
	}
	cwd, err = filepath.Abs(cwd)
	if err != nil {
		return "", nil
	}
	cwd = filepath.Clean(cwd)
	if cwdAlreadyMounted(a.Volumes, cwd) {
		return "", nil
	}
	if hasNeverMountDir(a.NeverMountDirs, cwd) {
		fmt.Fprintf(os.Stderr, "Skipping mount prompt for %s (directory marked never-mount): %s\n\n", agentName, cwd)
		return "", nil
	}
	if remembered := rememberedVolumeForCWD(a.RememberedVolumes, cwd); remembered != "" {
		fmt.Fprintf(os.Stderr, "Using remembered mount for %s: %s\n\n", agentName, remembered)
		return remembered, nil
	}

	target := nextCWDMountTarget(a.Volumes, filepath.Base(cwd))
	renderCWDMountMenu(agentName, cwd, target)

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", nil
		}
		choice, ok := parseCWDMountChoice(strings.TrimSpace(strings.ToLower(line)))
		if !ok {
			fmt.Fprintf(os.Stderr, "Invalid input. Enter 1-9: ")
			continue
		}
		return applyCWDMountChoice(mgr, agentName, a, cwd, target, choice)
	}
}


func renderCWDMountMenu(agentName, cwd, target string) {
	fmt.Fprintf(os.Stderr, "\n━━━ LOA: Directory Mount ━━━\n\n")
	fmt.Fprintf(os.Stderr, "🤖 Agent: %s\n", agentName)
	fmt.Fprintf(os.Stderr, "Directory: %s\n", cwd)
	fmt.Fprintf(os.Stderr, "Target:    %s\n\n", target)
	fmt.Fprintf(os.Stderr, "🟢 Save Allow Policy\n")
	fmt.Fprintf(os.Stderr, "1) %s allowed read %s\n", agentName, cwd)
	fmt.Fprintf(os.Stderr, "2) all agents allowed read %s\n", cwd)
	fmt.Fprintf(os.Stderr, "3) %s allowed read+write %s\n", agentName, cwd)
	fmt.Fprintf(os.Stderr, "4) all agents allowed read+write %s\n", cwd)
	fmt.Fprintf(os.Stderr, "\n🔴 Save Block Policy\n")
	fmt.Fprintf(os.Stderr, "5) %s blocked this directory\n", agentName)
	fmt.Fprintf(os.Stderr, "6) all agents blocked this directory\n")
	fmt.Fprintf(os.Stderr, "\n🟡 One-time\n")
	fmt.Fprintf(os.Stderr, "7) defer (block now, decide later)\n")
	fmt.Fprintf(os.Stderr, "8) %s allowed read once\n", agentName)
	fmt.Fprintf(os.Stderr, "9) %s allowed read+write once\n\n", agentName)
	fmt.Fprintf(os.Stderr, "Choose [1-9]: ")
}


type cwdMountChoice struct {
	skip      bool
	never     bool
	allAgents bool
	readOnly  bool
	remember  bool
}

func parseCWDMountChoice(input string) (cwdMountChoice, bool) {
	switch input {
	case "1":
		return cwdMountChoice{readOnly: true, remember: true}, true
	case "2":
		return cwdMountChoice{readOnly: true, remember: true, allAgents: true}, true
	case "3":
		return cwdMountChoice{remember: true}, true
	case "4":
		return cwdMountChoice{remember: true, allAgents: true}, true
	case "5":
		return cwdMountChoice{skip: true, never: true}, true
	case "6":
		return cwdMountChoice{skip: true, never: true, allAgents: true}, true
	case "7", "", "n", "no", "skip", "s":
		return cwdMountChoice{skip: true}, true
	case "8":
		return cwdMountChoice{readOnly: true}, true
	case "9":
		return cwdMountChoice{}, true
	default:
		return cwdMountChoice{}, false
	}
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func hasNeverMountDir(dirs []string, cwd string) bool {
	cwd = filepath.Clean(cwd)
	for _, d := range dirs {
		if filepath.Clean(d) == cwd {
			return true
		}
	}
	return false
}

func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
