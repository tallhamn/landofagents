package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "init":
		runInit(os.Args[2:])
	case "agent":
		runAgent(os.Args[2:])
	case "run":
		runRun(os.Args[2:])
	case "terminate":
		runTerminate(os.Args[2:])
	case "watch":
		runWatch(os.Args[2:])
	case "authz":
		runAuthz(os.Args[2:])
	case "inbox":
		runInbox(os.Args[2:])
	case "approve":
		runApprove(os.Args[2:])
	case "secret":
		runSecret(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "mounts":
		runMounts(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "protect":
		runProtect(os.Args[2:])
	case "doctor":
		runDoctor(os.Args[2:])
	case "worker":
		runWorker(os.Args[2:])
	case "control":
		runControl(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Land of Agents — liberate your agents safely

Usage:
  loa <command> [arguments]

Commands:
  init      Initialize a new LOA permission kit
  agent     Create and manage named agents
  run       Run an agent in a governed container
  terminate Stop active LOA containers for an agent
  watch     Watch for denials and approve in real-time
  inbox     Show pending denials
  approve   Review denied action and approve policy
  policy    List, inspect, and activate policies
  audit     Verify and inspect audit logs
  protect   Record one observed activity event into audit log
  doctor    Diagnose common LOA setup/runtime issues
  status    Show agent status and permissions
  mounts    Inspect/remove remembered per-directory mounts
  authz     Run the ext_authz server (used by Envoy sidecar)
  secret    Manage named secrets and per-agent secret grants
  worker    Launch/get/terminate/list governed detached workers (JSON API)
  control   GAP control-plane commands (spawn/status/terminate/list)
  serve     Run long-lived LOA services (for example: control socket server)
`)
}
