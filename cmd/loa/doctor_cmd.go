package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/config"
)

func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	agentName := fs.String("agent", "", "Agent name to inspect")
	verbose := fs.Bool("verbose", false, "Show full diagnostics")
	fs.Parse(args)

	kit := kitDir()
	auditDir := filepath.Join(kit, "audit")
	activePoliciesDir := filepath.Join(kit, "policies", "active")
	stagedPoliciesDir := filepath.Join(kit, "policies", "staged")
	kitSource := "default path (~/land-of-agents)"
	if strings.TrimSpace(os.Getenv("LOA_KIT")) != "" {
		kitSource = "$LOA_KIT"
	}
	target := "all agents"
	if strings.TrimSpace(*agentName) != "" {
		target = *agentName
	}
	fmt.Printf("🩺 LOA Doctor: %s\n", target)
	fmt.Println("────────────────────────────────────────")

	health := "OK"
	var healthReasons []string

	requiredDirs := []string{"config", "policies", "policies/staged", "policies/active", "audit"}
	missing := []string{}
	for _, sub := range requiredDirs {
		p := filepath.Join(kit, sub)
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			missing = append(missing, p)
		}
	}
	if len(missing) != 0 {
		health = "ATTENTION"
		healthReasons = append(healthReasons, "kit layout is missing required directories")
	}
	var agentRuntime, agentScope string
	agentMissing := false
	var agentConfig *agent.Agent
	if *agentName != "" {
		mgr := agent.NewManager(kit)
		a, err := mgr.Get(*agentName)
		if err != nil {
			health = "ATTENTION"
			healthReasons = append(healthReasons, fmt.Sprintf("agent %q not found", *agentName))
			agentMissing = true
		} else {
			agentConfig = &a
			agentRuntime = a.Runtime
			agentScope = a.Scope
		}
	}

	overall := "✅ Healthy"
	if health != "OK" {
		overall = "⚠️  Attention needed"
	}
	fmt.Printf("Overall: %s\n", overall)

	printDoctorSection("✅ Health")
	if health == "OK" {
		fmt.Printf("  Status: OK\n")
		fmt.Printf("  Summary: No configuration errors found\n")
	} else {
		fmt.Printf("  Status: ATTENTION\n")
		fmt.Printf("  Summary: %s\n", strings.Join(healthReasons, "; "))
	}

	printDoctorSection("🏠 LOA Home")
	fmt.Printf("  Selected by: %s\n", kitSource)
	if len(missing) == 0 {
		fmt.Printf("  Layout: OK\n")
	} else {
		fmt.Printf("  Layout: MISSING\n")
		fmt.Printf("  Fix: run 'loa init' (or 'go run ./cmd/loa init') with this same LOA_KIT.\n")
	}
	if *verbose {
		for _, p := range missing {
			fmt.Printf("  Missing: %s\n", p)
		}
	}

	if *agentName != "" {
		printDoctorSection("🤖 Agent")
		fmt.Printf("  Name: %s\n", *agentName)
		if agentMissing {
			fmt.Printf("  Status: NOT FOUND\n")
		} else {
			fmt.Printf("  Runtime: %s\n", agentRuntime)
			fmt.Printf("  Scope: %s\n", agentScope)
		}
	}

	reportContainment(*agentName, agentConfig)

	if *agentName != "" && !agentMissing {
		reportSecretExposure(kit, *agentName, agentConfig, *verbose)
	}

	reportAudit(kit, *agentName, *verbose)
	reportPolicies(kit, *agentName, *verbose)
	reportDocker(*agentName, *verbose)

	if *verbose {
		printDoctorSection("📁 Data Sources (used by this report)")
		agentRegistryPath := config.AgentRegistryPath(kit)
		fmt.Printf("  LOA home directory: %s (%s)\n", kit, pathKind(kit))
		if *agentName != "" {
			fmt.Printf("  agent registry (%s): %s (%s)\n", filepath.Base(agentRegistryPath), agentRegistryPath, pathKind(agentRegistryPath))
		}
		fmt.Printf("  audit log dir: %s (%s)\n", auditDir, pathKind(auditDir))
		fmt.Printf("  active policies dir: %s (%s)\n", activePoliciesDir, pathKind(activePoliciesDir))
		fmt.Printf("  staged policies dir: %s (%s)\n", stagedPoliciesDir, pathKind(stagedPoliciesDir))
	} else {
		printDoctorSection("📁 Data Sources")
		fmt.Printf("  LOA home: %s\n", kit)
	}

	if !*verbose {
		fmt.Println()
		fmt.Printf("Tip: run 'loa doctor --verbose")
		if *agentName != "" {
			fmt.Printf(" --agent %s", *agentName)
		}
		fmt.Printf("' for full diagnostics.\n")
	} else {
		printDoctorSection("⚙️  Environment")
		fmt.Printf("  Time: %s\n", time.Now().Format(time.RFC3339))
		exe, _ := os.Executable()
		fmt.Printf("  Executable: %s\n", exe)
		fmt.Printf("  Auth mode env: %s\n", valueOrDefault(os.Getenv("LOA_CLAUDE_AUTH_MODE"), "auto"))
		fmt.Printf("  Command policy env: %s\n", valueOrDefault(os.Getenv("LOA_COMMAND_POLICY_MODE"), "discover"))
	}
}


func printDoctorSection(title string) { printSection(title) }

func valueOrDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}


func reportContainment(agentName string, agentCfg *agent.Agent) {
	printDoctorSection("🧱 Containment")
	fmt.Printf("  Network: forced egress proxy (agent traffic exits via Envoy + authz).\n")
	if agentCfg != nil {
		fmt.Printf("  File system: mounted paths only (%d configured, %d remembered, %d never-mount).\n",
			len(agentCfg.Volumes), len(agentCfg.RememberedVolumes), len(agentCfg.NeverMountDirs))
	} else if strings.TrimSpace(agentName) != "" {
		fmt.Printf("  File system: mounted paths only (agent configuration unavailable).\n")
	} else {
		fmt.Printf("  File system: mounted paths only (inspect per-agent with 'loa mounts <agent>').\n")
	}
	if agentCfg != nil {
		fmt.Printf("  Secrets: runtime env allowlist + secret grants (%d env, %d refs).\n", len(agentCfg.AllowedEnv), len(agentCfg.AllowedSecrets))
	} else {
		fmt.Printf("  Secrets: runtime-declared environment variables only (see 'Secrets & Auth').\n")
	}
	fmt.Printf("  Activity: command/file/network audit stream (no command blocking).\n")
}
