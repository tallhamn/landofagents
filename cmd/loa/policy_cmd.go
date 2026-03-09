package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/netscope"
)

func runPolicy(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa policy <list|activate|effective|suggest> [arguments]\n")
		os.Exit(1)
	}

	pipeline := approval.NewPipeline(approval.PipelineConfig{KitDir: kitDir()})

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("policy list", flag.ExitOnError)
		stagedOnly := fs.Bool("staged", false, "Show staged policies only")
		activeOnly := fs.Bool("active", false, "Show active policies only")
		fs.Parse(args[1:])

		showStaged := *stagedOnly || (!*stagedOnly && !*activeOnly)
		showActive := *activeOnly || (!*stagedOnly && !*activeOnly)

		if showStaged {
			staged, err := pipeline.ListStagedPolicies()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listing staged policies: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("🟨 Staged (%d)\n", len(staged))
			if len(staged) == 0 {
				fmt.Printf("  (none)\n")
			} else {
				for _, name := range staged {
					fmt.Printf("  - %s\n", name)
				}
			}
			fmt.Println()
		}

		if showActive {
			active, err := pipeline.ListActivePolicies()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error listing active policies: %v\n", err)
				os.Exit(1)
			}
			info := readActivePolicyInfo(kitDir(), active)
			allow, deny, unknown := countPolicyEffects(info)
			allScope, agentScope := countPolicyScopes(info)
			fmt.Printf("🟢 Active (%d)\n", len(active))
			fmt.Printf("  Summary: %d allow, %d deny", allow, deny)
			if unknown > 0 {
				fmt.Printf(", %d unknown", unknown)
			}
			fmt.Printf("\n")
			fmt.Printf("  Scope: %d all-agents, %d agent-specific\n", allScope, agentScope)
			if len(info) == 0 {
				fmt.Printf("  (none)\n")
			} else {
				fmt.Printf("  Files:\n")
				for _, p := range info {
					scopeLabel := p.Scope
					if scopeLabel == "agent" {
						scopeLabel = "agent"
					} else {
						scopeLabel = "all"
					}
					fmt.Printf("    - [%s|%s] %s\n", scopeLabel, p.Effect, p.Name)
				}
			}
		}

	case "activate":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: loa policy activate <filename|all>\n")
			os.Exit(1)
		}
		target := args[1]
		if target == "all" {
			activated, err := pipeline.ActivateAllStaged()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error activating staged policies: %v\n", err)
				os.Exit(1)
			}
			if len(activated) == 0 {
				fmt.Println("No staged policies to activate.")
				return
			}
			fmt.Printf("Activated %d policies:\n", len(activated))
			for _, path := range activated {
				fmt.Printf("  %s\n", filepath.Base(path))
			}
			return
		}

		path, err := pipeline.ActivateStagedByName(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error activating policy: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Activated: %s\n", filepath.Base(path))
	case "effective":
		runPolicyEffective(args[1:])
	case "suggest":
		runPolicySuggest(args[1:])

	default:
		fmt.Fprintf(os.Stderr, "Unknown policy subcommand: %s\n", args[0])
		os.Exit(1)
	}
}


func applyNetworkScope(prop approval.ProposalWithCedar, denials []audit.Record, networkScope approval.NetworkScope) approval.ProposalWithCedar {
	if networkScope != approval.NetworkScopeDomain {
		return prop
	}

	for _, d := range denials {
		if d.Action != "http:Request" {
			continue
		}
		host := netscope.NormalizeHost(d.Resource)
		if host == "" {
			continue
		}
		domain := netscope.EffectiveDomain(host)
		if domain == "" || domain == host {
			continue
		}
		prop.Cedar = strings.ReplaceAll(prop.Cedar, fmt.Sprintf(`Resource::"%s"`, host), fmt.Sprintf(`Resource::"%s"`, domain))
		prop.Description = strings.ReplaceAll(prop.Description, host, domain)
		prop.Filename = strings.ReplaceAll(prop.Filename, host, domain)
	}
	return prop
}

func timeSince(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// rewriteForAllAgents strips the agent-specific principal from Cedar and adjusts the filename.
func rewriteForAllAgents(prop approval.ProposalWithCedar) approval.ProposalWithCedar {
	// Replace `principal == Agent::"<name>"` with bare `principal`
	prop.Cedar = strings.Replace(
		prop.Cedar,
		fmt.Sprintf(`principal == Agent::"%s"`, prop.Agent),
		"principal",
		1,
	)
	// Prefix filename with "all-" instead of agent name
	if strings.HasPrefix(prop.Filename, prop.Agent+"-") {
		prop.Filename = "all-" + strings.TrimPrefix(prop.Filename, prop.Agent+"-")
	} else {
		prop.Filename = "all-" + prop.Filename
	}
	return prop
}

func rewriteForbidPolicy(prop approval.ProposalWithCedar) approval.ProposalWithCedar {
	if strings.Contains(prop.Cedar, "forbid(") {
		return prop
	}
	if strings.Contains(prop.Cedar, "permit(") {
		prop.Cedar = strings.Replace(prop.Cedar, "permit(", "forbid(", 1)
	}
	if strings.HasSuffix(prop.Filename, ".cedar") && !strings.Contains(prop.Filename, "-forbid.") {
		prop.Filename = strings.TrimSuffix(prop.Filename, ".cedar") + "-forbid.cedar"
	}
	return prop
}
