package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
)

func runControl(args []string) {
	if len(args) == 0 {
		controlUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "spawn":
		runControlSpawn(args[1:])
	case "status":
		runControlStatus(args[1:])
	case "terminate":
		runControlTerminate(args[1:])
	case "list":
		runControlList(args[1:])
	default:
		controlUsage()
		os.Exit(1)
	}
}

func controlUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  loa control spawn --request-json <path> [--socket <path>]
  loa control spawn --agent <name> --session-id <id> --workload-id <id> [--parent-worker-id <id>] [--volume ...]
  loa control status --worker-id <id> [--socket <path>]
  loa control terminate --worker-id <id> [--reason <text>] [--socket <path>]
  loa control list [--socket <path>]

Requires a running control server:
  loa serve control [--socket <path>]
`)
}

func runControlSpawn(args []string) {
	fs := flag.NewFlagSet("control spawn", flag.ExitOnError)
	socket := fs.String("socket", controlSocketPath(), "Unix socket path for loa serve control")
	reqPath := fs.String("request-json", "", "Path to GAP spawn request JSON")
	requestID := fs.String("request-id", "", "Request ID")
	agentName := fs.String("agent", "", "Agent name")
	sessionID := fs.String("session-id", "", "Session ID")
	workloadID := fs.String("workload-id", "", "Workload/task ID")
	parentWorkerID := fs.String("parent-worker-id", "", "Optional parent worker ID")
	runtimeName := fs.String("runtime", "openclaw-worker", "Worker runtime label")
	networkMode := fs.String("mode", "enforce", "Network mode: enforce|log|ask")
	initialScope := fs.String("initial-policy-scope", "existing-active", "Initial policy scope label")
	exposure := fs.String("secret-exposure", "least", "Secret exposure profile label")
	var volumes repeatableFlag
	var secretRefs repeatableFlag
	var labels keyValueFlag
	var envVars keyValueFlag
	fs.Var(&volumes, "volume", "Mount volume (repeatable host:container[:ro|rw])")
	fs.Var(&secretRefs, "secret-ref", "Secret reference name (repeatable)")
	fs.Var(&labels, "label", "Label key=value (repeatable)")
	fs.Var(&envVars, "env", "Caller env var key=value (repeatable, intersected with agent allowed_env)")
	fs.Parse(args)

	req, err := buildControlSpawnRequest(controlSpawnInput{
		RequestPath:    strings.TrimSpace(*reqPath),
		RequestID:      strings.TrimSpace(*requestID),
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
		Env:            envVars.Clone(),
	})
	if err != nil {
		exitControlError(err)
	}

	client := newControlClient(strings.TrimSpace(*socket))
	resp, err := client.Spawn(context.Background(), req)
	if err != nil {
		exitControlError(err)
	}
	writeControlJSON(resp)
	if resp.Decision != "permit" {
		os.Exit(3)
	}
}

func runControlStatus(args []string) {
	fs := flag.NewFlagSet("control status", flag.ExitOnError)
	socket := fs.String("socket", controlSocketPath(), "Unix socket path for loa serve control")
	requestID := fs.String("request-id", "", "Request ID")
	workerID := fs.String("worker-id", "", "Worker ID")
	fs.Parse(args)

	client := newControlClient(strings.TrimSpace(*socket))
	resp, err := client.Status(context.Background(), gapcontrol.WorkerStatusRequest{
		Version:   gapcontrol.VersionV1,
		RequestID: strings.TrimSpace(*requestID),
		WorkerID:  strings.TrimSpace(*workerID),
	})
	if err != nil {
		exitControlError(err)
	}
	writeControlJSON(resp)
}

func runControlTerminate(args []string) {
	fs := flag.NewFlagSet("control terminate", flag.ExitOnError)
	socket := fs.String("socket", controlSocketPath(), "Unix socket path for loa serve control")
	requestID := fs.String("request-id", "", "Request ID")
	workerID := fs.String("worker-id", "", "Worker ID")
	reason := fs.String("reason", "", "Termination reason")
	fs.Parse(args)

	client := newControlClient(strings.TrimSpace(*socket))
	resp, err := client.Terminate(context.Background(), gapcontrol.TerminateRequest{
		Version:   gapcontrol.VersionV1,
		RequestID: strings.TrimSpace(*requestID),
		WorkerID:  strings.TrimSpace(*workerID),
		Reason:    strings.TrimSpace(*reason),
	})
	if err != nil {
		exitControlError(err)
	}
	writeControlJSON(resp)
	if resp.Decision != "permit" {
		os.Exit(3)
	}
}

func runControlList(args []string) {
	fs := flag.NewFlagSet("control list", flag.ExitOnError)
	socket := fs.String("socket", controlSocketPath(), "Unix socket path for loa serve control")
	requestID := fs.String("request-id", "", "Request ID")
	fs.Parse(args)

	client := newControlClient(strings.TrimSpace(*socket))
	resp, err := client.List(context.Background(), strings.TrimSpace(*requestID))
	if err != nil {
		exitControlError(err)
	}
	writeControlJSON(resp)
}
