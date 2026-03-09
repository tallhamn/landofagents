package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/marcusmom/land-of-agents/engine/agent"
)

func runAgent(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa agent <create|delete|list> [arguments]\n")
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		runAgentCreate(args[1:])
	case "delete":
		runAgentDelete(args[1:])
	case "list":
		runAgentList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown agent subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

// volumeFlags collects repeatable --volume flags.
type volumeFlags []string

func (v *volumeFlags) String() string { return fmt.Sprintf("%v", *v) }
func (v *volumeFlags) Set(val string) error {
	*v = append(*v, val)
	return nil
}

func runAgentCreate(args []string) {
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !isFlag(a) {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	if name == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa agent create <name> --runtime <runtime> [--volume <src>:<dst>] [--allow-env VAR] [--allow-secret REF]\n")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("agent create", flag.ExitOnError)
	rtName := fs.String("runtime", "claude-code", "Runtime for the agent (see runtimes/)")
	modeName := fs.String("mode", "", "Policy mode: ask (default), log, or enforce")
	var volumes volumeFlags
	var allowedEnv volumeFlags
	var allowedSecrets volumeFlags
	fs.Var(&volumes, "volume", "Volume mount (repeatable, e.g. ./code:/workspace)")
	fs.Var(&allowedEnv, "allow-env", "Allow runtime env var passthrough for this agent (repeatable)")
	fs.Var(&allowedSecrets, "allow-secret", "Allow named secret reference for this agent (repeatable)")
	fs.Parse(flagArgs)

	opts := agent.CreateOpts{
		Runtime:        *rtName,
		Mode:           *modeName,
		Volumes:        volumes,
		AllowedEnv:     allowedEnv,
		AllowedSecrets: allowedSecrets,
	}

	mgr := agent.NewManager(kitDir())
	if err := mgr.Create(name, opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created agent: %s\n", name)
	fmt.Printf("  Runtime: %s\n", opts.Runtime)
	fmt.Printf("  Scope: %s\n", name)
	if len(volumes) > 0 {
		fmt.Printf("  Volumes:\n")
		for _, v := range volumes {
			fmt.Printf("    %s\n", v)
		}
	}
	if len(allowedEnv) > 0 {
		fmt.Printf("  Allowed env:\n")
		for _, e := range allowedEnv {
			fmt.Printf("    %s\n", e)
		}
	}
	if len(allowedSecrets) > 0 {
		fmt.Printf("  Allowed secrets:\n")
		for _, s := range allowedSecrets {
			fmt.Printf("    %s\n", s)
		}
	}
}

func runAgentDelete(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa agent delete <name>\n")
		os.Exit(1)
	}
	name := args[0]

	mgr := agent.NewManager(kitDir())
	if err := mgr.Delete(name); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deleted agent: %s\n", name)
}

func runAgentList(args []string) {
	mgr := agent.NewManager(kitDir())
	agents, err := mgr.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(agents) == 0 {
		fmt.Println("No agents. Create one with: loa agent create <name> --runtime claude-code")
		return
	}

	fmt.Printf("Agents (%d):\n", len(agents))
	for _, a := range agents {
		fmt.Printf("  %-15s  runtime: %s  scope: %s\n", a.Name, a.Runtime, a.Scope)
	}
}
