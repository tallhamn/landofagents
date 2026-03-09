package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	gaptrail "github.com/marcusmom/land-of-agents/gap/trail"
	"github.com/marcusmom/land-of-agents/engine/services/loaledger"
)

func runProtect(args []string) {
	fs := flag.NewFlagSet("protect", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name")
	command := fs.String("command", "", "Shell command to evaluate")
	stage := fs.String("stage", "pre", "Activity stage: pre (command) or post (file update scan)")
	fileRoot := fs.String("file-root", "/workspace", "Root directory to scan for changed files in post stage")
	sinceFile := fs.String("since-file", "", "Snapshot file path used as a timestamp marker for post stage scans")
	maxFiles := fs.Int("max-files", 20, "Maximum number of changed file paths to store in one activity event")
	fs.Parse(args)

	if *agentName == "" || *command == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa protect --agent <name> --command <shell command>\n")
		os.Exit(1)
	}

	// Observation-only: no command denial/enforcement. Record shell activity for auditing.
	ledger, err := loaledger.New(kitDir())
	if err != nil {
		return
	}

	agent := strings.TrimSpace(*agentName)
	cmd := strings.TrimSpace(*command)
	switch strings.ToLower(strings.TrimSpace(*stage)) {
	case "", "pre":
		if err := ledger.AppendEvent(gaptrail.Event{
			Version:      gaptrail.VersionV1,
			EventType:    "command.exec",
			AgentID:      agent,
			Scope:        agent,
			Action:       "exec:Run",
			Resource:     shellResourceFromCommand(cmd),
			Decision:     "permit",
			DecisionPath: "activity_exec",
			Context: map[string]any{
				"command": cmd,
			},
		}); err != nil {
			return
		}
	case "post":
		root := strings.TrimSpace(*fileRoot)
		snap := strings.TrimSpace(*sinceFile)
		files, total, err := collectChangedFilesSince(root, snap, *maxFiles)
		if err != nil || total == 0 {
			return
		}
		ctx := map[string]any{
			"command":     cmd,
			"root":        root,
			"files":       files,
			"total_files": total,
			"truncated":   total > len(files),
		}
		if err := ledger.AppendEvent(gaptrail.Event{
			Version:      gaptrail.VersionV1,
			EventType:    "filesystem.access",
			AgentID:      agent,
			Scope:        agent,
			Action:       "file:UpdateSet",
			Resource:     root,
			Decision:     "permit",
			DecisionPath: "activity_file",
			Context:      ctx,
		}); err != nil {
			return
		}
	default:
		return
	}
}
