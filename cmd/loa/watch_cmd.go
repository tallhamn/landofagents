package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/audit"
)

func runWatch(args []string) {
	var agentName string
	var flagArgs []string
	for _, a := range args {
		if agentName == "" && !isFlag(a) {
			agentName = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	verbose := fs.Bool("verbose", false, "Show live policy decision events (permit/deny)")
	fs.Parse(flagArgs)
	dir := kitDir()

	if agentName != "" {
		mgr := agent.NewManager(dir)
		if _, err := mgr.Get(agentName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nStopped watching.\n")
		cancel()
		// Prompt reads can block on stdin; force-exit if shutdown doesn't complete quickly.
		time.AfterFunc(1200*time.Millisecond, func() {
			os.Exit(130)
		})
	}()
	if err := runWatchLoop(ctx, watchLoopConfig{
		KitDir:      dir,
		AgentName:   agentName,
		Verbose:     *verbose,
		Inline:      false,
		PrintHeader: true,
	}); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type watchLoopConfig struct {
	KitDir      string
	AgentName   string
	Verbose     bool
	Inline      bool
	PrintHeader bool
}

func runWatchLoop(ctx context.Context, cfg watchLoopConfig) error {
	auditDir := filepath.Join(cfg.KitDir, "audit")
	watcher := approval.NewWatcher(auditDir, cfg.AgentName)
	watcher.SetIncludePermits(cfg.Verbose)
	batchCh := watcher.Watch(ctx)
	burstFilter := newDenyBurstFilter(3 * time.Second)
	recentApprovals := newApprovedTracker(10 * time.Second)

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	pipeline := approval.NewPipeline(approval.PipelineConfig{
		KitDir: cfg.KitDir,
		APIKey: apiKey,
	})

	if cfg.PrintHeader {
		if apiKey == "" {
			fmt.Fprintf(os.Stderr, "No LLM configured — discuss unavailable.\n")
		}
		target := "all agents"
		if cfg.AgentName != "" {
			target = cfg.AgentName
		}
		switch {
		case cfg.Inline:
			fmt.Fprintf(os.Stderr, "Watching %s inline gate approvals... (Ctrl-C to stop)\n\n", target)
		case cfg.Verbose:
			fmt.Fprintf(os.Stderr, "Watching %s activity and policy events... (Ctrl-C to stop)\n\n", target)
		default:
			fmt.Fprintf(os.Stderr, "Watching %s approval queue... (Ctrl-C to stop)\n\n", target)
		}
		fmt.Fprintf(os.Stderr, "Policy store: %s\n\n", filepath.Join(cfg.KitDir, "policies", "active"))
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case batch, ok := <-batchCh:
			if !ok {
				return nil
			}
			if cfg.Verbose {
				printWatchEvents(batch)
			}
			// In verbose mode the watcher streams permit+deny events without batch dedupe.
			// Normalize and suppress short bursts so operators don't get prompt storms.
			now := time.Now()
			denials := deduplicateDeniedRecords(batch)
			denials = burstFilter.Filter(denials, now)
			// Skip denials already covered by a policy just applied — show info instead of re-prompting.
			denials, covered := recentApprovals.Filter(denials, now)
			for _, r := range covered {
				fmt.Fprintf(os.Stderr, "  ↳ %s — covered by policy just applied\n", r.Resource)
			}
			if len(denials) == 0 {
				continue
			}
			approved := handleBatch(ctx, pipeline, cfg.KitDir, apiKey, denials)
			recentApprovals.Mark(approved, time.Now())
		}
	}
}

func printWatchEvents(records []audit.Record) {
	for _, r := range records {
		event := renderAuditEventParts(r)
		switch event.Decision {
		case "permit":
			fmt.Fprintf(os.Stderr, "✅ %s 🤖 %s %s [%s]\n", event.Timestamp, r.Agent, event.Target, event.Path)
			if extra := fileActivityLine(r); extra != "" {
				fmt.Fprintf(os.Stderr, "   files: %s\n", extra)
			}
		case "deny":
			fmt.Fprintf(os.Stderr, "⏸️  %s 🤖 %s %s [%s]\n", event.Timestamp, r.Agent, event.Target, event.Path)
			if event.ShowReason {
				fmt.Fprintf(os.Stderr, "   reason: %s\n", event.Reason)
			}
		default:
			fmt.Fprintf(os.Stderr, "ℹ️  %s 🤖 %s %s [%s]\n", event.Timestamp, r.Agent, event.Target, event.Path)
		}
	}
}
