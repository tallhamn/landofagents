package main

import (
	"fmt"
	"os"

	"github.com/marcusmom/land-of-agents/engine/agent"
)

func applyCWDMountChoice(mgr *agent.Manager, agentName string, a *agent.Agent, cwd, target string, choice cwdMountChoice) (string, error) {
	if choice.skip {
		if choice.never {
			if choice.allAgents {
				if err := mgr.AddNeverMountDirAll(cwd); err != nil {
					return "", err
				}
				fmt.Fprintf(os.Stderr, "\n🔴 Saved: all agents will never auto-mount this directory.\n")
			} else {
				if err := mgr.AddNeverMountDir(agentName, cwd); err != nil {
					return "", err
				}
				if !hasNeverMountDir(a.NeverMountDirs, cwd) {
					a.NeverMountDirs = append(a.NeverMountDirs, cwd)
				}
				fmt.Fprintf(os.Stderr, "\n🔴 Saved: %s will never auto-mount this directory.\n", agentName)
			}
			fmt.Fprintf(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		}
		return "", nil
	}

	volume := fmt.Sprintf("%s:%s", cwd, target)
	if choice.readOnly {
		volume += ":ro"
	}
	fmt.Fprintf(os.Stderr, "\n🟢 Mounting for this run: %s\n", volume)
	if choice.remember {
		if choice.allAgents {
			if err := mgr.AddRememberedVolumeAll(volume); err != nil {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "🟢 Saved for all agents from this exact directory.\n")
		} else {
			if err := mgr.AddRememberedVolume(agentName, volume); err != nil {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "🟢 Saved for %s from this exact directory.\n", agentName)
		}
		if !containsString(a.RememberedVolumes, volume) {
			a.RememberedVolumes = append(a.RememberedVolumes, volume)
		}
	}
	fmt.Fprintf(os.Stderr, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	return volume, nil
}
