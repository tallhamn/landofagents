package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/audit"
)

func runMountWizardForDenial(reader *bufio.Reader, kitDir string, d audit.Record) error {
	mgr := agent.NewManager(kitDir)
	agentCfg, err := mgr.Get(d.Agent)
	if err != nil {
		return err
	}

	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	hostDefault := cwd
	targetDefault := suggestedContainerMountTarget(d.Resource)
	if targetDefault == "" {
		targetDefault = nextCWDMountTarget(agentCfg.Volumes, filepath.Base(hostDefault))
	}

	fmt.Fprintf(os.Stderr, "\nMount wizard for %s\n", d.Agent)
	fmt.Fprintf(os.Stderr, "Host directory [%s]: ", hostDefault)
	hostPath, err := readLineDefault(reader, hostDefault)
	if err != nil {
		return err
	}
	hostPath = expandHome(strings.TrimSpace(hostPath))
	hostPath, err = filepath.Abs(hostPath)
	if err != nil {
		return fmt.Errorf("resolve host path: %w", err)
	}
	info, err := os.Stat(hostPath)
	if err != nil {
		return fmt.Errorf("host path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("host path must be a directory: %s", hostPath)
	}

	fmt.Fprintf(os.Stderr, "Container target [%s]: ", targetDefault)
	targetPath, err := readLineDefault(reader, targetDefault)
	if err != nil {
		return err
	}
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" || !strings.HasPrefix(targetPath, "/") {
		return fmt.Errorf("container target must be an absolute path")
	}

	fmt.Fprintf(os.Stderr, "Mount mode [rw/ro] [rw]: ")
	mode, err := readLineDefault(reader, "rw")
	if err != nil {
		return err
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "rw" && mode != "ro" {
		return fmt.Errorf("mount mode must be rw or ro")
	}

	volume := fmt.Sprintf("%s:%s", hostPath, targetPath)
	if mode == "ro" {
		volume += ":ro"
	}
	if err := mgr.AddVolume(d.Agent, volume); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "🟢 Added mount for %s: %s\n", d.Agent, volume)
	fmt.Fprintf(os.Stderr, "Restart the agent run to apply this mount.\n")
	fmt.Fprintf(os.Stderr, "  1) Stop current run\n")
	fmt.Fprintf(os.Stderr, "  2) loa run %s\n\n", d.Agent)
	return nil
}

func suggestedContainerMountTarget(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" || !strings.HasPrefix(resource, "/") {
		return ""
	}
	clean := path.Clean(resource)
	base := path.Base(clean)
	if strings.Contains(base, ".") {
		clean = path.Dir(clean)
	}
	if clean == "." {
		return ""
	}
	return clean
}

func readLineDefault(reader *bufio.Reader, def string) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return def, nil
	}
	return value, nil
}
