package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func runAudit(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa audit <verify|summary>\n")
		os.Exit(1)
	}

	switch args[0] {
	case "verify":
		runAuditVerify()
	case "summary":
		runAuditSummary(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown audit subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func runAuditVerify() {
	logger, err := audit.NewLogger(filepath.Join(kitDir(), "audit"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	report, err := logger.VerifyAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Audit verification summary\n")
	fmt.Printf("  Files checked: %d\n", report.FilesChecked)
	fmt.Printf("  Records read:  %d\n", report.RecordsRead)
	fmt.Printf("  Failures:      %d\n", len(report.Failures))
	if len(report.Failures) == 0 {
		fmt.Println("Integrity check: PASS")
		return
	}

	fmt.Println("Integrity check: FAIL")
	for _, f := range report.Failures {
		fmt.Printf("  %s:%d  %s\n", f.File, f.Line, f.Reason)
	}
	os.Exit(1)
}
