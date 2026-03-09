package contain

import (
	"fmt"
	"os"

	"github.com/marcusmom/land-of-agents/engine/config"
	"github.com/marcusmom/land-of-agents/engine/runtimehooks"
)

// Run sets up and starts the governed container environment (foreground, blocking).
func Run(opts Options) error {
	if !hasTTY(os.Stdin) || !hasTTY(os.Stdout) {
		return fmt.Errorf("loa run requires an interactive terminal (TTY on stdin/stdout)")
	}

	env, err := SetupEnvironment(opts)
	if err != nil {
		return err
	}

	kit, _ := config.LoadKit(opts.KitDir)
	agentConfig, _ := kit.GetAgent(opts.AgentName)
	rt, _ := kit.LoadAgentRuntime(opts.AgentName)

	var volumes []string
	for _, v := range agentConfig.Volumes {
		volumes = append(volumes, v)
	}
	volumes = append(volumes, opts.ExtraVolumes...)

	mode := opts.Mode
	proxyPort := opts.ProxyPort
	if proxyPort == 0 {
		proxyPort = 10000
	}
	agentPort := opts.AgentPort
	if agentPort == 0 {
		agentPort = 9002
	}

	runtimeDisplay := agentConfig.Runtime
	hookName := ""
	if rt != nil {
		hookName = rt.Hook
	}

	fmt.Printf("\nStarting governed environment for %s (mode: %s)...\n", opts.AgentName, mode)
	fmt.Printf("  Envoy proxy:  port %d\n", proxyPort)
	fmt.Printf("  LOA authz:    port %d\n", agentPort)
	fmt.Printf("  Runtime:      %s\n", runtimeDisplay)
	if env.AuthMode != "" {
		fmt.Printf("  Auth mode:    %s\n", env.AuthMode)
		if billingPath := runtimehooks.BillingPath(hookName, env.AuthMode); billingPath != "" {
			fmt.Printf("  Billing path: %s\n", billingPath)
		}
	}
	printEffectiveMounts(opts, volumes)
	fmt.Println()

	composeEnv := append(os.Environ(), fmt.Sprintf("LOA_KIT=%s", env.KitDir))

	if rt != nil {
		for _, envVar := range env.RuntimeEnv {
			if os.Getenv(envVar) == "" {
				fmt.Fprintf(os.Stderr, "Note: %s not set\n", envVar)
			}
		}
	}

	return runComposeSession(env.ComposePath, composeEnv, opts.AgentName, nil)
}

func hasTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
