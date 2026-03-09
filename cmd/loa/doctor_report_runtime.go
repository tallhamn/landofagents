package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func reportDocker(agentName string, verbose bool) {
	printDoctorSection("🐳 Runtime")

	cmd := exec.Command("docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Command}}")
	out, err := cmd.Output()
	if err != nil {
		fmt.Printf("  Status: unavailable (%v)\n", err)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		fmt.Printf("  LOA containers running: 0\n")
		return
	}

	var matched []string
	var authzMode string
	agentActive := 0
	for _, line := range lines {
		if !strings.Contains(line, "loa-contain-") {
			continue
		}
		if agentName != "" && !strings.Contains(line, "-"+agentName+"-") && !strings.Contains(line, "-loa-authz-") && !strings.Contains(line, "-envoy-") {
			continue
		}
		matched = append(matched, line)
		if agentName != "" && strings.Contains(line, "-"+agentName+"-run-") {
			agentActive++
		}
		if strings.Contains(line, "-loa-authz-") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) == 3 {
				authzMode = parseAuthzMode(parts[2])
			}
		}
	}

	if len(matched) == 0 {
		fmt.Printf("  LOA containers running: 0\n")
		return
	}
	if agentName != "" {
		fmt.Printf("  %s active containers: %d\n", agentName, agentActive)
		fmt.Printf("  LOA containers total: %d\n", len(matched))
	} else {
		fmt.Printf("  LOA containers running: %d\n", len(matched))
	}
	if verbose {
		for _, line := range matched {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) >= 2 {
				fmt.Printf("  Container: %s|%s\n", parts[0], parts[1])
			} else {
				fmt.Printf("  Container: %s\n", line)
			}
		}
	}
	if authzMode != "" && verbose {
		fmt.Printf("  Runtime authz mode: %s\n", authzMode)
	}
}

func pathKind(p string) string {
	info, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "missing"
		}
		return "unreadable"
	}
	if info.IsDir() {
		return "dir"
	}
	return "file"
}
