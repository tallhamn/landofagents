package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marcusmom/land-of-agents/app/approval"
)

func reportPolicies(kit, agentName string, verbose bool) {
	printDoctorSection("🛡 Policies (Active)")

	pipeline := approval.NewPipeline(approval.PipelineConfig{KitDir: kit})
	active, err := pipeline.ListActivePolicies()
	if err != nil {
		fmt.Printf("  Status: read error (%v)\n", err)
		return
	}
	sort.Strings(active)
	if agentName == "" {
		fmt.Printf("  Total active policies: %d\n", len(active))
		return
	}

	prefix := agentName + "-"
	var relevant []string
	for _, n := range active {
		switch {
		case strings.HasPrefix(n, prefix):
			relevant = append(relevant, n)
		case strings.HasPrefix(n, "all-"):
			relevant = append(relevant, n)
		}
	}
	info := readActivePolicyInfo(kit, relevant)
	allAllow, allDeny, allUnknown := countPolicyEffects(filterPolicyScope(info, "all"))
	agentAllow, agentDeny, agentUnknown := countPolicyEffects(filterPolicyScope(info, "agent"))

	fmt.Printf("  Total affecting %s: %d\n", agentName, len(info))
	fmt.Printf("  %s: %d allow, %d deny", agentName, agentAllow, agentDeny)
	if agentUnknown > 0 {
		fmt.Printf(", %d unknown", agentUnknown)
	}
	fmt.Printf("\n")
	fmt.Printf("  all agents: %d allow, %d deny", allAllow, allDeny)
	if allUnknown > 0 {
		fmt.Printf(", %d unknown", allUnknown)
	}
	fmt.Printf("\n")
	if len(info) == 0 || !verbose {
		return
	}
	fmt.Printf("  Files:\n")
	for _, p := range info {
		scopeLabel := agentName
		if p.Scope == "all" {
			scopeLabel = "all"
		}
		fmt.Printf("    - [%s|%s] %s\n", scopeLabel, p.Effect, p.Name)
	}
}
