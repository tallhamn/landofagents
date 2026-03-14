package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marcusmom/land-of-agents/app/approval"
)

type policyListEntry struct {
	agent     string
	resources []string
	source    string
}

type parsedPolicy struct {
	name  string
	rules []cedarRule
	agent string // extracted principal, or "all agents"
}

func runPolicyList(kit string, pipeline *approval.Pipeline) {
	active, err := pipeline.ListActivePolicies()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing active policies: %v\n", err)
		os.Exit(1)
	}
	if len(active) == 0 {
		fmt.Printf("No active policies.\n")
		return
	}

	var policies []parsedPolicy
	var empty []string // files with no rules (comment-only runtime placeholders)

	for _, name := range active {
		path := filepath.Join(kit, "policies", "active", name)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		rules := extractCedarRules(string(data))
		// If the only rule is the unknown fallback, it's an empty/comment-only file.
		if len(rules) == 1 && rules[0].Effect == "unknown" && rules[0].Action == "*" {
			empty = append(empty, name)
			continue
		}

		// Extract principal agent name.
		agent := "all agents"
		if m := cedarPrincipalPattern.FindStringSubmatch(string(data)); len(m) == 2 {
			agent = m[1]
		}

		policies = append(policies, parsedPolicy{
			name:  name,
			rules: rules,
			agent: agent,
		})
	}

	// Group rules by effect → agent → resources.
	allowByAgent := map[string]*policyListEntry{}
	denyByAgent := map[string]*policyListEntry{}

	for _, p := range policies {
		for _, r := range p.rules {
			target := allowByAgent
			if r.Effect == "deny" {
				target = denyByAgent
			}
			key := p.agent
			ar, ok := target[key]
			if !ok {
				ar = &policyListEntry{agent: key, source: p.name}
				target[key] = ar
			}
			resource := r.Resource
			if resource == "*" {
				resource = "(all)"
			}
			ar.resources = append(ar.resources, resource)
		}
	}

	// Deduplicate resources per agent.
	dedup := func(items []string) []string {
		seen := map[string]bool{}
		var out []string
		for _, s := range items {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}

	sortedAgents := func(m map[string]*policyListEntry) []*policyListEntry {
		out := make([]*policyListEntry, 0, len(m))
		for _, ar := range m {
			ar.resources = dedup(ar.resources)
			out = append(out, ar)
		}
		sort.Slice(out, func(i, j int) bool {
			// "all agents" sorts last.
			if out[i].agent == "all agents" {
				return false
			}
			if out[j].agent == "all agents" {
				return true
			}
			return out[i].agent < out[j].agent
		})
		return out
	}

	allowCount := 0
	denyCount := 0
	for _, ar := range allowByAgent {
		allowCount += len(ar.resources)
	}
	for _, ar := range denyByAgent {
		denyCount += len(ar.resources)
	}

	fmt.Printf("Active policies: %d files, %d allow rules, %d deny rules\n\n", len(active), allowCount, denyCount)

	printRuleSection("Allow", sortedAgents(allowByAgent))
	printRuleSection("Deny", sortedAgents(denyByAgent))

	if len(empty) > 0 {
		fmt.Printf("  Placeholder (no rules): %s\n", strings.Join(empty, ", "))
	}
}

func printRuleSection(label string, agents []*policyListEntry) {
	if len(agents) == 0 {
		fmt.Printf("  %s: (none)\n", label)
		return
	}
	fmt.Printf("  %s:\n", label)

	// Find longest agent name for alignment.
	maxLen := 0
	for _, ar := range agents {
		if len(ar.agent) > maxLen {
			maxLen = len(ar.agent)
		}
	}

	for _, ar := range agents {
		fmt.Printf("    %-*s  %s\n", maxLen, ar.agent, strings.Join(ar.resources, ", "))
	}
	fmt.Println()
}
