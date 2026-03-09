package approval

import (
	"fmt"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func (p *Prompter) askStandardDecision(proposal ProposalWithCedar, denials []audit.Record) (PromptResult, error) {
	for {
		if p.apiKey != "" {
			fmt.Fprintf(p.out, "\n[%s]pprove  [%s]eject  [S]kip  [D]iscuss: ", p.green("A"), p.red("R"))
		} else {
			fmt.Fprintf(p.out, "\n[%s]pprove  [%s]eject  [S]kip: ", p.green("A"), p.red("R"))
		}
		line, err := p.in.ReadString('\n')
		if err != nil {
			return PromptResult{Decision: Skipped}, err
		}
		input := normalizePromptInput(line)
		switch input {
		case "a":
			scope, err := p.askScope()
			if err != nil {
				return PromptResult{Decision: Skipped}, err
			}
			fmt.Fprintf(p.out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			return PromptResult{
				Decision:     Approved,
				Scope:        scope,
				NetworkScope: NetworkScopeHost,
				Effect:       PolicyPermit,
			}, nil
		case "r":
			fmt.Fprintf(p.out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			return PromptResult{Decision: Rejected}, nil
		case "s":
			fmt.Fprintf(p.out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			return PromptResult{Decision: Skipped}, nil
		case "d":
			if p.apiKey != "" {
				if err := p.discuss(denials, proposal); err != nil {
					fmt.Fprintf(p.out, "Discuss error: %v\n", err)
				}
			} else {
				fmt.Fprintf(p.out, "Invalid input. Enter a, r, or s.\n")
			}
		default:
			if p.apiKey != "" {
				fmt.Fprintf(p.out, "Invalid input. Enter a, r, s, or d.\n")
			} else {
				fmt.Fprintf(p.out, "Invalid input. Enter a, r, or s.\n")
			}
		}
	}
}

// askScope prompts the user to choose between agent-only or all-agents scope.
func (p *Prompter) askScope() (Scope, error) {
	name := p.agentName
	if name == "" {
		name = "this agent"
	}
	for {
		fmt.Fprintf(p.out, "Scope: [1] %s only / [2] all agents: ", name)
		line, err := p.in.ReadString('\n')
		if err != nil {
			return AgentOnly, err
		}
		input := normalizePromptInput(line)
		switch input {
		case "1", "", "agent", "a":
			return AgentOnly, nil
		case "2", "all":
			return AllAgents, nil
		default:
			fmt.Fprintf(p.out, "Invalid input.\n")
		}
	}
}

func indentLines(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func shouldAskNetworkScope(denials []audit.Record) bool {
	for _, d := range denials {
		if d.Action == "http:Request" && d.Resource != "" {
			return true
		}
	}
	return false
}

func hasFSDenial(denials []audit.Record) bool {
	for _, d := range denials {
		if strings.HasPrefix(d.Action, "fs:") {
			return true
		}
	}
	return false
}
