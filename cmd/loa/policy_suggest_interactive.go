package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/netscope"
	"github.com/marcusmom/land-of-agents/app/services/loaadvisor"
)

func runPolicySuggestInteractive(advisor *loaadvisor.Service, agentName, kit string, suggestions []loaadvisor.NetworkSuggestion, limit int, networkScope string) {
	if len(suggestions) == 0 {
		return
	}
	max := len(suggestions)
	if max > limit {
		max = limit
	}
	fmt.Println()
	fmt.Printf("Interactive review (network)\n")

	pipeline := approval.NewPipeline(approval.PipelineConfig{KitDir: kit})
	reader := bufio.NewReader(os.Stdin)
	for i := 0; i < max; i++ {
		s := suggestions[i]
		hostAllow := advisor.NetworkSuggestionProposal(agentName, s, "allow")
		hostBlock := advisor.NetworkSuggestionProposal(agentName, s, "deny")
		domain := netscope.EffectiveDomain(s.Resource)
		hasBroader := networkScope == "host" && domain != "" && domain != s.Resource
		var domainAllow approval.ProposalWithCedar
		var domainBlock approval.ProposalWithCedar
		if hasBroader {
			domainSuggestion := s
			domainSuggestion.Resource = domain
			domainAllow = advisor.NetworkSuggestionProposal(agentName, domainSuggestion, "allow")
			domainBlock = advisor.NetworkSuggestionProposal(agentName, domainSuggestion, "deny")
		}

		fmt.Println()
		fmt.Println("━━━ LOA: Suggested Policy ━━━")
		fmt.Println()
		fmt.Printf("🤖 %s was blocked from %s\n", agentName, s.Resource)
		fmt.Printf("Observed: %d blocked request%s (last %s)\n", s.Count, pluralSuffix(s.Count), s.LastSeen.Local().Format("15:04:05"))
		fmt.Println()
		if hasBroader {
			fmt.Println(gradientMenuLine(0, fmt.Sprintf("activate allow *.%s (all %s hosts)", domain, domain), true))
			fmt.Println(gradientMenuLine(1, fmt.Sprintf("activate allow %s", s.Resource), true))
			fmt.Println(gradientMenuLine(2, fmt.Sprintf("activate block %s", s.Resource), true))
			fmt.Println(gradientMenuLine(3, fmt.Sprintf("activate block *.%s (all %s hosts)", domain, domain), true))
			fmt.Println("q) quit review")
		} else {
			fmt.Println(gradientMenuLine(0, fmt.Sprintf("activate allow %s", s.Resource), false))
			fmt.Println(gradientMenuLine(1, fmt.Sprintf("activate block %s", s.Resource), false))
			fmt.Println("q) quit review")
		}
		for {
			if hasBroader {
				fmt.Printf("Choose [0-3] (or q): ")
			} else {
				fmt.Printf("Choose [0-1] (or q): ")
			}
			line, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("\nInput closed. Ending interactive review.\n")
				return
			}
			choice := strings.TrimSpace(strings.ToLower(line))
			if choice == "" {
				choice = "0"
			}
			switch choice {
			case "0":
				prop := hostAllow
				if hasBroader {
					prop = domainAllow
				}
				if !activateSuggestedPolicy(pipeline, prop, false) {
					break
				}
				goto nextSuggestion
			case "2":
			case "3":
				if !hasBroader {
					fmt.Printf("Invalid input. Enter %s.\n", suggestChoiceHelp(hasBroader))
					break
				}
				var prop approval.ProposalWithCedar
				if choice == "2" {
					prop = hostBlock
				} else {
					prop = domainBlock
				}
				if !activateSuggestedPolicy(pipeline, prop, true) {
					break
				}
				goto nextSuggestion
			case "1":
				if hasBroader {
					if !activateSuggestedPolicy(pipeline, hostAllow, false) {
						break
					}
					goto nextSuggestion
				}
				if !activateSuggestedPolicy(pipeline, hostBlock, true) {
					break
				}
				goto nextSuggestion
			case "q":
				fmt.Printf("Stopped interactive review.\n")
				return
			default:
				fmt.Printf("Invalid input. Enter %s.\n", suggestChoiceHelp(hasBroader))
			}
		}
	nextSuggestion:
	}
	fmt.Printf("\nReview complete. Use 'loa policy list --staged' or '--active' to inspect results.\n")
}

func activateSuggestedPolicy(pipeline *approval.Pipeline, prop approval.ProposalWithCedar, isBlock bool) bool {
	applyResult, err := stageAndMaybeActivatePolicy(pipeline, prop, true)
	if err != nil {
		fmt.Printf("Error applying policy: %v\n", err)
		return false
	}
	if isBlock {
		fmt.Printf("🔴 Activated block: %s\n", filepath.Base(applyResult.ActivePath))
	} else {
		fmt.Printf("🟢 Activated: %s\n", filepath.Base(applyResult.ActivePath))
	}
	return true
}

func suggestChoiceHelp(hasBroader bool) string {
	if hasBroader {
		return "0/1/2/3 or q"
	}
	return "0/1 or q"
}
