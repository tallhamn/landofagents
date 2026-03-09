package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/marcusmom/land-of-agents/app/approval"
)

func readActivePolicyInfo(kitDir string, names []string) []activePolicyInfo {
	info := make([]activePolicyInfo, 0, len(names))
	for _, n := range names {
		scope := "agent"
		if strings.HasPrefix(n, "all-") {
			scope = "all"
		}
		effect := "unknown"
		content, err := os.ReadFile(filepath.Join(kitDir, "policies", "active", n))
		if err == nil {
			effect = policyEffectFromCedar(string(content))
		}
		info = append(info, activePolicyInfo{
			Name:   n,
			Scope:  scope,
			Effect: effect,
		})
	}
	return info
}

func filterPolicyScope(info []activePolicyInfo, scope string) []activePolicyInfo {
	var out []activePolicyInfo
	for _, p := range info {
		if p.Scope == scope {
			out = append(out, p)
		}
	}
	return out
}

func countPolicyEffects(info []activePolicyInfo) (allow, deny, unknown int) {
	for _, p := range info {
		switch p.Effect {
		case "allow":
			allow++
		case "deny":
			deny++
		default:
			unknown++
		}
	}
	return
}

func countPolicyScopes(info []activePolicyInfo) (allScope, agentScope int) {
	for _, p := range info {
		if p.Scope == "all" {
			allScope++
		} else {
			agentScope++
		}
	}
	return
}

func loadEffectivePolicyEntries(kitDir, agentName string) ([]effectivePolicyEntry, error) {
	var entries []effectivePolicyEntry

	alwaysAllowedPath := filepath.Join(kitDir, "config", "always-allowed.cedar")
	if data, err := os.ReadFile(alwaysAllowedPath); err == nil {
		for _, r := range extractCedarRules(string(data)) {
			entries = append(entries, effectivePolicyEntry{
				Effect:   r.Effect,
				Action:   r.Action,
				Resource: r.Resource,
				Scope:    "all",
				Source:   filepath.Base(alwaysAllowedPath),
			})
		}
	}

	pipeline := approval.NewPipeline(approval.PipelineConfig{KitDir: kitDir})
	active, err := pipeline.ListActivePolicies()
	if err != nil {
		return nil, err
	}
	sort.Strings(active)
	for _, name := range active {
		scope, applies := policyScopeForAgent(name, agentName)
		if !applies {
			continue
		}
		path := filepath.Join(kitDir, "policies", "active", name)
		data, err := os.ReadFile(path)
		if err != nil {
			entries = append(entries, effectivePolicyEntry{
				Effect:   "unknown",
				Action:   "*",
				Resource: "*",
				Scope:    scope,
				Source:   name,
			})
			continue
		}
		for _, r := range extractCedarRules(string(data)) {
			entries = append(entries, effectivePolicyEntry{
				Effect:   r.Effect,
				Action:   r.Action,
				Resource: r.Resource,
				Scope:    scope,
				Source:   name,
			})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Action != entries[j].Action {
			return entries[i].Action < entries[j].Action
		}
		if entries[i].Effect != entries[j].Effect {
			return entries[i].Effect < entries[j].Effect
		}
		if entries[i].Resource != entries[j].Resource {
			return entries[i].Resource < entries[j].Resource
		}
		return entries[i].Source < entries[j].Source
	})
	return entries, nil
}

func countEffectiveEntryEffects(entries []effectivePolicyEntry) (allow, deny, unknown int) {
	for _, e := range entries {
		switch e.Effect {
		case "allow":
			allow++
		case "deny":
			deny++
		default:
			unknown++
		}
	}
	return
}

func collectNetworkEffective(entries []effectivePolicyEntry) (allow []string, deny []string) {
	allowSet := map[string]bool{}
	denySet := map[string]bool{}
	for _, e := range entries {
		if e.Action != "http:Request" || strings.TrimSpace(e.Resource) == "" || e.Resource == "*" {
			continue
		}
		label := e.Resource
		if e.Scope == "all" {
			label += " (all agents)"
		}
		switch e.Effect {
		case "allow":
			allowSet[label] = true
		case "deny":
			denySet[label] = true
		}
	}
	return sortedKeys(allowSet), sortedKeys(denySet)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}


func policyScopeForAgent(policyName, agentName string) (scope string, applies bool) {
	if strings.HasPrefix(policyName, "all-") {
		return "all", true
	}
	if strings.HasPrefix(policyName, agentName+"-") || strings.HasPrefix(policyName, "_runtime-"+agentName) {
		return "agent", true
	}
	return "", false
}

func extractCedarRules(cedar string) []cedarRule {
	matches := cedarStmtPattern.FindAllStringSubmatch(cedar, -1)
	if len(matches) == 0 {
		return []cedarRule{{Effect: "unknown", Action: "*", Resource: "*"}}
	}
	rules := make([]cedarRule, 0, len(matches))
	for _, m := range matches {
		effect := "unknown"
		switch strings.ToLower(strings.TrimSpace(m[1])) {
		case "permit":
			effect = "allow"
		case "forbid":
			effect = "deny"
		}
		body := m[2]
		action := "*"
		resource := "*"
		if sm := cedarActionPattern.FindStringSubmatch(body); len(sm) == 2 {
			action = sm[1]
		}
		if sm := cedarResourcePattern.FindStringSubmatch(body); len(sm) == 2 {
			resource = sm[1]
		}
		rules = append(rules, cedarRule{
			Effect:   effect,
			Action:   action,
			Resource: resource,
		})
	}
	return rules
}

func policyEffectFromCedar(cedar string) string {
	lower := strings.ToLower(cedar)
	permitIdx := strings.Index(lower, "permit(")
	forbidIdx := strings.Index(lower, "forbid(")
	switch {
	case permitIdx >= 0 && (forbidIdx < 0 || permitIdx < forbidIdx):
		return "allow"
	case forbidIdx >= 0 && (permitIdx < 0 || forbidIdx < permitIdx):
		return "deny"
	default:
		return "unknown"
	}
}

func parseAuthzMode(command string) string {
	patterns := []string{
		`--mode" "?([a-z]+)`,
		`--mode ([a-z]+)`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		m := re.FindStringSubmatch(command)
		if len(m) == 2 {
			return m[1]
		}
	}
	return ""
}


func formatCSV(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func printMountCategory(label string, mounts []string) {
	fmt.Printf("%s: ", label)
	if len(mounts) == 0 {
		fmt.Printf("(none)\n")
		return
	}
	fmt.Printf("\n")
	for _, m := range mounts {
		host, container, mode := parseMountSpec(m)
		fmt.Printf("    - %s -> %s (%s)\n", host, container, mode)
	}
}

func printPathCategory(label string, paths []string) {
	fmt.Printf("%s: ", label)
	if len(paths) == 0 {
		fmt.Printf("(none)\n")
		return
	}
	fmt.Printf("\n")
	for _, p := range paths {
		fmt.Printf("    - %s\n", p)
	}
}
