package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func runAuditSummary(args []string) {
	fs := flag.NewFlagSet("audit summary", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name filter")
	since := fs.String("since", "", "Only include events from this recent duration (e.g. 1h, 30m)")
	fs.Parse(args)

	sinceCutoff, err := parseSinceCutoff(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid --since duration: %v\n", err)
		os.Exit(1)
	}

	logger, err := audit.NewLogger(filepath.Join(kitDir(), "audit"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	records, err := logger.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	agent := strings.TrimSpace(*agentName)
	summary := collectActivitySummary(records, agent, sinceCutoff)

	target := "all agents"
	if agent != "" {
		target = agent
	}
	window := "all time"
	if !sinceCutoff.IsZero() {
		window = "last " + strings.TrimSpace(*since)
	}

	fmt.Printf("Activity summary (%s, %s)\n", target, window)
	fmt.Printf("  Events: %d\n", summary.events)
	fmt.Printf("  Commands observed: %d\n", summary.commandEvents)
	fmt.Printf("  Network requests: %d\n", summary.httpEvents)
	fmt.Printf("  File update batches: %d\n", summary.fileBatches)
	fmt.Printf("  Files updated (reported): %d\n", summary.fileUpdates)
	if !summary.first.IsZero() {
		fmt.Printf("  Time range: %s -> %s\n", summary.first.Local().Format(time.RFC3339), summary.last.Local().Format(time.RFC3339))
	}
	printTopCounts("Top hosts", summary.hosts, 5)
	printTopCounts("Top files", summary.files, 8)
}

func parseSinceCutoff(since string) (time.Time, error) {
	since = strings.TrimSpace(since)
	if since == "" {
		return time.Time{}, nil
	}
	d, err := time.ParseDuration(since)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(-d), nil
}
