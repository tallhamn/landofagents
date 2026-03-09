package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func partitionFilesystemDenials(denials []audit.Record) (fsDenials, other []audit.Record) {
	for _, d := range denials {
		if strings.HasPrefix(strings.TrimSpace(d.Action), "fs:") {
			fsDenials = append(fsDenials, d)
			continue
		}
		other = append(other, d)
	}
	return fsDenials, other
}

func handleFilesystemDenials(kitDir string, denials []audit.Record) []audit.Record {
	fsDenials, other := partitionFilesystemDenials(denials)
	if len(fsDenials) == 0 {
		return denials
	}

	first := fsDenials[0]
	renderFilesystemRequestHeader(first, len(fsDenials)-1)
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return other
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "m":
			if err := runMountWizardForDenial(reader, kitDir, first); err != nil {
				fmt.Fprintf(os.Stderr, "Mount wizard error: %v\n", err)
			}
			return other
		case "p":
			return denials
		case "s", "":
			return other
		default:
			fmt.Fprintf(os.Stderr, "Invalid input. Enter m, p, or s: ")
		}
	}
}

func renderFilesystemRequestHeader(first audit.Record, additionalCount int) {
	fmt.Fprintf(os.Stderr, "\n━━━ LOA: Filesystem Access Request ━━━\n\n")
	fmt.Fprintf(os.Stderr, "🤖 Agent: %s\n", first.Agent)
	fmt.Fprintf(os.Stderr, "⏸️  Denied: %s -> %s\n", first.Action, first.Resource)
	if first.DenialReason != "" {
		fmt.Fprintf(os.Stderr, "   reason: %s\n", first.DenialReason)
	}
	if additionalCount > 0 {
		fmt.Fprintf(os.Stderr, "   + %d additional filesystem denials in this batch\n", additionalCount)
	}
	fmt.Fprintf(os.Stderr, "\nChoose next step:\n")
	fmt.Fprintf(os.Stderr, "  [M] Add directory mount for next run\n")
	fmt.Fprintf(os.Stderr, "  [P] Continue with policy proposal flow\n")
	fmt.Fprintf(os.Stderr, "  [S] Skip filesystem denials for now\n")
	fmt.Fprintf(os.Stderr, "Choice [m/p/s]: ")
}
