package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/authz"
	"github.com/marcusmom/land-of-agents/engine/services/loaledger"
)

func runAuthz(args []string) {
	fs := flag.NewFlagSet("authz", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name to authorize for")
	port := fs.Int("port", 9002, "Port to listen on")
	mode := fs.String("mode", "enforce", "Mode: enforce, log, or ask")
	fs.Parse(args)

	if *agentName == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa authz --agent <name> [--port 9002] [--mode ask]\n")
		os.Exit(1)
	}

	dir := kitDir()

	mgr := agent.NewManager(dir)
	if _, err := mgr.Get(*agentName); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ledger, err := loaledger.New(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating audit ledger: %v\n", err)
		os.Exit(1)
	}

	normalizedMode := strings.ToLower(strings.TrimSpace(*mode))

	srv := authz.NewServer(dir, *agentName, strings.TrimSpace(os.Getenv("LOA_RUN_ID")), ledger, authz.Mode(normalizedMode))
	addr := fmt.Sprintf(":%d", *port)
	fmt.Printf("LOA ext_authz server — agent: %s, mode: %s, listening on %s\n", *agentName, normalizedMode, addr)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runInbox(args []string) {
	dir := kitDir()
	denials, err := loadPendingReviewDenials(dir, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading pending review queue: %v\n", err)
		os.Exit(1)
	}

	if len(denials) == 0 {
		fmt.Println("No pending denials.")
		return
	}

	fmt.Printf("📥 Pending review queue (%d)\n\n", len(denials))
	for i, d := range denials {
		event := renderAuditEventParts(d)
		fmt.Printf("  #%d  ⏸️  🤖 %s  %s  [%s]", i+1, d.Agent, event.Target, event.Path)
		if !d.Timestamp.IsZero() {
			fmt.Printf("  (%s)", timeSince(d.Timestamp))
		}
		fmt.Printf("\n")
		if event.ShowReason {
			fmt.Printf("       reason: %s\n", event.Reason)
		}
	}
	fmt.Printf("\nApprove with: loa approve <number>\n")
}
