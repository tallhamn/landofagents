package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/audit"
)

func runApprove(args []string) {
	var numArg string
	var flagArgs []string
	for _, a := range args {
		if numArg == "" && !isFlag(a) {
			numArg = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	if numArg == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa approve <number> [--network-scope host|domain]\n")
		os.Exit(1)
	}
	var num int
	if _, err := fmt.Sscanf(numArg, "%d", &num); err != nil || num < 1 {
		fmt.Fprintf(os.Stderr, "Error: invalid denial number %q\n", numArg)
		os.Exit(1)
	}
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	networkScope := fs.String("network-scope", "host", "Network scope for http:Request (host|domain)")
	fs.Parse(flagArgs)
	if *networkScope != "host" && *networkScope != "domain" {
		fmt.Fprintf(os.Stderr, "Error: --network-scope must be host or domain\n")
		os.Exit(1)
	}

	dir := kitDir()
	denials, err := loadPendingReviewDenials(dir, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading pending review queue: %v\n", err)
		os.Exit(1)
	}

	if num > len(denials) {
		fmt.Fprintf(os.Stderr, "Error: denial #%d not found (have %d denials)\n", num, len(denials))
		os.Exit(1)
	}

	d := denials[num-1]
	if isUnmappedDeniedRecord(d) {
		fmt.Printf("⏸️ Blocked request is unmapped (%s)\n", d.DecisionPath)
		fmt.Printf("  Action:   %s\n", d.Action)
		fmt.Printf("  Resource: %s\n", d.Resource)
		if d.DenialReason != "" {
			fmt.Printf("  Reason:   %s\n", d.DenialReason)
		}
		fmt.Printf("\nNo Cedar policy will fix this. Update command mappings in config/protector.yml or keep it blocked.\n")
		return
	}

	// Use the shared pipeline
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	pipeline := approval.NewPipeline(approval.PipelineConfig{
		KitDir: dir,
		APIKey: apiKey,
	})

	if apiKey == "" {
		fmt.Println("(no ANTHROPIC_API_KEY — using fallback)")
	}

	result, err := pipeline.Process(context.Background(), []audit.Record{d})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	for _, prop := range result.Proposals {
		scope := approval.NetworkScopeHost
		if *networkScope == "domain" {
			scope = approval.NetworkScopeDomain
		} else if !hasFlag(flagArgs, "--network-scope") && d.Action == "http:Request" {
			scope = promptNetworkScope(os.Stdin, os.Stderr, d.Resource)
		}
		prop = applyNetworkScope(prop, []audit.Record{d}, scope)

		fmt.Printf("Permission Request: %s\n", blueURLs(prop.Description))
		if prop.Reasoning != "" {
			fmt.Printf("  Reasoning: %s\n", prop.Reasoning)
		}

		renderedPolicy := approval.FormatCedarForDisplay(prop.Cedar, os.Stdout)
		fmt.Printf("\nPolicy Preview:\n%s\n", indentLines(blueURLs(renderedPolicy), "  "))

		activePath, err := applyPolicy(pipeline, prop)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error applying policy: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nActivated: %s\n", filepath.Base(activePath))
	}

	fmt.Printf("\n🟢 Approved for %s: can now %s %s.\n", d.Agent, d.Action, blueURLs(d.Resource))
}
