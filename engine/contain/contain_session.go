package contain

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

func runComposeSession(composePath string, composeEnv []string, agentName string, externalSignals <-chan os.Signal) error {
	// Start infrastructure (authz + envoy) in background.
	fmt.Println("Starting infrastructure...")
	up := exec.Command("docker", "compose", "-f", composePath, "up", "-d", "--build", "loa-authz", "envoy")
	up.Stdout = os.Stdout
	up.Stderr = os.Stderr
	up.Env = composeEnv
	if err := up.Run(); err != nil {
		return fmt.Errorf("docker compose up (infra): %w", err)
	}
	defer func() {
		fmt.Println("\nStopping containers...")
		down := exec.Command("docker", "compose", "-f", composePath, "down")
		down.Stdout = os.Stdout
		down.Stderr = os.Stderr
		down.Env = composeEnv
		_ = down.Run()
	}()

	// Run agent interactively — stdin/stdout/stderr fully attached.
	fmt.Println("Starting agent...")
	run := exec.Command("docker", "compose", "-f", composePath, "run", "--rm", "--service-ports", agentName)
	run.Stdout = os.Stdout
	run.Stderr = os.Stderr
	run.Stdin = os.Stdin
	run.Env = composeEnv
	if err := run.Start(); err != nil {
		return fmt.Errorf("docker compose run (agent): %w", err)
	}

	sigCh := externalSignals
	var internalSigCh chan os.Signal
	if sigCh == nil {
		internalSigCh = make(chan os.Signal, 2)
		signal.Notify(internalSigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(internalSigCh)
		sigCh = internalSigCh
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- run.Wait()
	}()

	var (
		agentExitCode int
		agentExitErr  error
		interrupted   bool
	)
	for {
		select {
		case err := <-waitCh:
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					agentExitCode = ee.ExitCode()
					agentExitErr = err
				} else {
					return fmt.Errorf("docker compose run (agent): %w", err)
				}
			}
			goto done
		case sig := <-sigCh:
			if sig == nil {
				continue
			}
			interrupted = true
			if run.Process != nil {
				_ = run.Process.Signal(sig)
			}
		}
	}

done:
	if interrupted {
		return fmt.Errorf("agent interrupted")
	}
	if agentExitErr != nil {
		return fmt.Errorf("agent exited with status %d", agentExitCode)
	}
	return nil
}

// TerminateAgentStacks removes LOA containers/networks for the given agent.
// It only targets stacks that have a matching "<agent>-run-" container prefix.
func TerminateAgentStacks(agentName string) (int, error) {
	if strings.TrimSpace(agentName) == "" {
		return 0, fmt.Errorf("agent name is required")
	}
	prefixes, err := staleComposePrefixesForAgent(agentName)
	if err != nil {
		return 0, err
	}
	if len(prefixes) == 0 {
		return 0, nil
	}

	containers, err := listDockerContainerNames(true)
	if err != nil {
		return 0, err
	}
	terminated := 0
	for _, prefix := range prefixes {
		var toRemove []string
		for _, name := range containers {
			if !strings.HasPrefix(name, prefix+"-") {
				continue
			}
			if strings.Contains(name, "-loa-authz-") || strings.Contains(name, "-envoy-") || strings.Contains(name, "-"+agentName+"-run-") {
				toRemove = append(toRemove, name)
			}
		}
		if len(toRemove) > 0 {
			if err := exec.Command("docker", append([]string{"rm", "-f"}, toRemove...)...).Run(); err != nil {
				return terminated, err
			}
		}
		for _, netName := range []string{prefix + "_agent-net", prefix + "_external-net"} {
			_ = exec.Command("docker", "network", "rm", netName).Run()
		}
		terminated++
	}
	return terminated, nil
}

func staleComposePrefixesForAgent(agentName string) ([]string, error) {
	names, err := listDockerContainerNames(true)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var prefixes []string
	for _, name := range names {
		prefix, ok := composePrefixFromRunContainerName(name, agentName)
		if !ok || seen[prefix] {
			continue
		}
		seen[prefix] = true
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func listDockerContainerNames(all bool) ([]string, error) {
	args := []string{"ps", "--format", "{{.Names}}"}
	if all {
		args = []string{"ps", "-a", "--format", "{{.Names}}"}
	}
	cmd := exec.Command("docker", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(bytes.TrimSpace(out), []byte{'\n'})
	var names []string
	for _, ln := range lines {
		name := strings.TrimSpace(string(ln))
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func composePrefixFromRunContainerName(containerName, agentName string) (string, bool) {
	needle := "-" + agentName + "-run-"
	i := strings.Index(containerName, needle)
	if i <= 0 {
		return "", false
	}
	prefix := containerName[:i]
	if !strings.HasPrefix(prefix, "loa-contain-") {
		return "", false
	}
	return prefix, true
}
