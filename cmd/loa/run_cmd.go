package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/app/adapters/openclaw"
	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/contain"
)

func runRun(args []string) {
	var agentName string
	var flagArgs []string

	for _, a := range args {
		if isFlag(a) {
			flagArgs = append(flagArgs, a)
		} else if agentName == "" {
			agentName = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	if agentName == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa run <agent> [--inline]\n")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	inline := fs.Bool("inline", false, "Inline approvals in this terminal (ask mode only, experimental)")
	fs.Parse(flagArgs)

	dir := kitDir()
	mgr := agent.NewManager(dir)
	agentCfg, err := mgr.Get(agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := validateOpenClawBackend(agentCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	mode := agentCfg.EffectiveMode()

	if *inline {
		if mode != "ask" {
			fmt.Fprintf(os.Stderr, "Error: --inline requires ask mode (agent %s is in %s mode)\n", agentName, mode)
			os.Exit(1)
		}
		if reason, ok := inlineUnsupportedReason(agentCfg); ok {
			fmt.Fprintf(os.Stderr, "Error: --inline is not supported for %s.\n", reason)
			fmt.Fprintf(os.Stderr, "Why: this runtime uses a full-screen terminal UI that overwrites inline prompts.\n")
			fmt.Fprintf(os.Stderr, "Use two terminals instead:\n")
			fmt.Fprintf(os.Stderr, "  1) loa run %s\n", agentName)
			fmt.Fprintf(os.Stderr, "  2) loa watch %s\n", agentName)
			os.Exit(1)
		}
	}
	if mode == "ask" && !*inline {
		fmt.Fprintf(os.Stderr, "Ask mode requires an approver.\n")
		fmt.Fprintf(os.Stderr, "In another terminal, run: loa watch %s\n\n", agentName)
	}

	extraVolume, err := maybeOfferCWDMount(mgr, agentName, &agentCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var extraVolumes []string
	if extraVolume != "" {
		extraVolumes = []string{extraVolume}
	}

	var inlineCancel context.CancelFunc
	var inlineDone chan error
	if *inline {
		fmt.Fprintf(os.Stderr, "LOA inline approvals enabled for %s. Approval prompts will appear in this terminal.\n\n", agentName)
		inlineCtx, cancel := context.WithCancel(context.Background())
		inlineCancel = cancel
		inlineDone = make(chan error, 1)
		go func() {
			inlineDone <- runWatchLoop(inlineCtx, watchLoopConfig{
				KitDir:      dir,
				AgentName:   agentName,
				Verbose:     false,
				Inline:      true,
				PrintHeader: true,
			})
		}()
	}

	if err := contain.Run(contain.Options{
		KitDir:       dir,
		AgentName:    agentName,
		Mode:         mode,
		ExtraVolumes: extraVolumes,
	}); err != nil {
		if inlineCancel != nil {
			inlineCancel()
			select {
			case watchErr := <-inlineDone:
				if watchErr != nil && !errors.Is(watchErr, context.Canceled) {
					fmt.Fprintf(os.Stderr, "Inline watch error: %v\n", watchErr)
				}
			case <-time.After(2 * time.Second):
			}
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if inlineCancel != nil {
		inlineCancel()
		select {
		case watchErr := <-inlineDone:
			if watchErr != nil && !errors.Is(watchErr, context.Canceled) {
				fmt.Fprintf(os.Stderr, "Inline watch error: %v\n", watchErr)
			}
		case <-time.After(2 * time.Second):
		}
	}
}

func isOpenClawRuntime(a agent.Agent) bool {
	return openclaw.IsRuntime(a.Runtime)
}

func openclawRequireWorkerAPI() bool {
	return openclaw.IsEnabled()
}

func validateOpenClawBackend(a agent.Agent) error {
	if err := openclaw.ValidateRunPreflight(a.Runtime); err != nil {
		return err
	}
	if !openclaw.IsStrictForRuntime(a.Runtime) {
		return nil
	}
	forbidden := openclaw.ForbiddenVolumeSources(a.Volumes)
	if len(forbidden) > 0 {
		return fmt.Errorf("openclaw secure mode forbids mounting container runtime sockets: %s", strings.Join(forbidden, ", "))
	}
	return nil
}
