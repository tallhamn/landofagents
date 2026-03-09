package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func reportAudit(kit, agentName string, verbose bool) {
	printDoctorSection("📜 Activity (Audit Log)")

	logger, err := audit.NewLogger(filepath.Join(kit, "audit"))
	if err != nil {
		fmt.Printf("  Status: unavailable (%v)\n", err)
		return
	}
	records, err := logger.ReadAll()
	if err != nil {
		fmt.Printf("  Status: read error (%v)\n", err)
		return
	}

	total := len(records)
	denies := 0
	var lastDeny time.Time
	for _, r := range records {
		if r.Decision != "deny" {
			continue
		}
		denies++
		if r.Timestamp.After(lastDeny) {
			lastDeny = r.Timestamp
		}
	}
	pending := pendingReviewDenials(records, agentName)

	fmt.Printf("  Audit events recorded: %d\n", total)
	fmt.Printf("  Blocked events recorded: %d\n", denies)
	if agentName != "" {
		fmt.Printf("  Pending review: %d unique blocked actions (%s)\n", len(pending), agentName)
	}
	if !lastDeny.IsZero() {
		fmt.Printf("  Last denial: %s (%s)\n", lastDeny.Local().Format(time.RFC3339), timeSince(lastDeny))
	}
	if verbose && len(pending) > 0 {
		fmt.Printf("  Note: 'loa watch' only shows new denials after it starts. Use 'loa inbox' for existing ones.\n")
	}
}
