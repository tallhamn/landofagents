package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

func runWorker(args []string) {
	if len(args) == 0 {
		workerUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "launch":
		runWorkerLaunch(args[1:])
	case "get":
		runWorkerGet(args[1:])
	case "terminate":
		runWorkerTerminate(args[1:])
	case "list":
		runWorkerList(args[1:])
	default:
		workerUsage()
		os.Exit(1)
	}
}

func workerUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  loa worker launch --request-json <path>
  loa worker launch --agent <name> --session-id <id> --workload-id <id> [--parent-worker-id <id>] [--volume ...]
  loa worker get --worker-id <id>
  loa worker terminate --worker-id <id> [--reason <text>]
  loa worker list
`)
}

func runWorkerLaunch(args []string) {
	fs := flag.NewFlagSet("worker launch", flag.ExitOnError)
	reqPath := fs.String("request-json", "", "Path to launch request JSON")
	agentName := fs.String("agent", "", "Agent name")
	sessionID := fs.String("session-id", "", "Session ID")
	workloadID := fs.String("workload-id", "", "Workload/task ID")
	parentWorkerID := fs.String("parent-worker-id", "", "Optional parent worker ID for child launch attribution")
	runtimeName := fs.String("runtime", "openclaw-worker", "Worker runtime label")
	networkMode := fs.String("mode", "enforce", "Network mode: enforce|log|ask")
	initialScope := fs.String("initial-policy-scope", "existing-active", "Initial policy scope label")
	exposure := fs.String("secret-exposure", "least", "Secret exposure profile label")
	var volumes repeatableFlag
	var secretRefs repeatableFlag
	var labels keyValueFlag
	fs.Var(&volumes, "volume", "Mount volume (repeatable host:container[:ro|rw])")
	fs.Var(&secretRefs, "secret-ref", "Secret reference name (repeatable)")
	fs.Var(&labels, "label", "Label key=value (repeatable)")
	fs.Parse(args)

	req, err := buildLaunchRequest(launchRequestInput{
		RequestPath:    strings.TrimSpace(*reqPath),
		Agent:          strings.TrimSpace(*agentName),
		SessionID:      strings.TrimSpace(*sessionID),
		WorkloadID:     strings.TrimSpace(*workloadID),
		ParentWorkerID: strings.TrimSpace(*parentWorkerID),
		Runtime:        strings.TrimSpace(*runtimeName),
		Mode:           strings.TrimSpace(*networkMode),
		InitialScope:   strings.TrimSpace(*initialScope),
		SecretExposure: strings.TrimSpace(*exposure),
		Volumes:        append([]string{}, volumes...),
		SecretRefs:     append([]string{}, secretRefs...),
		Labels:         labels.Clone(),
	})
	if err != nil {
		exitWorkerError(err)
	}
	if strings.TrimSpace(req.PrincipalID) == "" {
		req.PrincipalID = fmt.Sprintf("uid:%d", os.Getuid())
	}
	resp, err := runWorkerLaunchCompat(context.Background(), req)
	if err != nil {
		exitWorkerError(err)
	}
	writeWorkerJSON(resp)
}

func runWorkerGet(args []string) {
	fs := flag.NewFlagSet("worker get", flag.ExitOnError)
	workerID := fs.String("worker-id", "", "Worker ID")
	fs.Parse(args)
	resp, err := runWorkerGetCompat(context.Background(), strings.TrimSpace(*workerID))
	if err != nil {
		exitWorkerError(err)
	}
	writeWorkerJSON(resp)
}

func runWorkerTerminate(args []string) {
	fs := flag.NewFlagSet("worker terminate", flag.ExitOnError)
	workerID := fs.String("worker-id", "", "Worker ID")
	reason := fs.String("reason", "", "Termination reason")
	fs.Parse(args)
	resp, err := runWorkerTerminateCompat(context.Background(), strings.TrimSpace(*workerID), strings.TrimSpace(*reason))
	if err != nil {
		exitWorkerError(err)
	}
	writeWorkerJSON(resp)
}

func runWorkerList(args []string) {
	fs := flag.NewFlagSet("worker list", flag.ExitOnError)
	fs.Parse(args)
	resp, err := runWorkerListCompat(context.Background())
	if err != nil {
		exitWorkerError(err)
	}
	writeWorkerJSON(resp)
}
