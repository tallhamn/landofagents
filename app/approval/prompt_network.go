package approval

import (
	"fmt"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/netscope"
)

// askNetworkDecision presents a single-step numeric menu grouped by:
// add allow policy, add block policy, and one-time actions.
func (p *Prompter) askNetworkDecision(proposal ProposalWithCedar, denials []audit.Record) (PromptResult, error) {
	host, domain := networkScopeExample(denials)
	if host == "" {
		host = "this host"
	}
	if domain == "" {
		domain = host
	}
	agent := proposal.Agent
	if strings.TrimSpace(agent) == "" {
		agent = p.agentName
	}
	if strings.TrimSpace(agent) == "" {
		agent = "agent"
	}
	agentShort := truncateLabel(agent, 24)
	hostLabel := p.blue(host)
	domainDisplay := domain
	if domainDisplay != host {
		domainDisplay = "*." + domain
	}
	domainLabel := p.blue(domainDisplay)
	hostOnly := strings.EqualFold(strings.TrimSpace(domain), strings.TrimSpace(host))
	menu := buildNetworkDecisionMenu(agentShort, hostLabel, domainLabel, hostOnly)
	maxChoice := menu.maxIndex()
	choiceRange := fmt.Sprintf("0-%d", maxChoice)

	for {
		if hostOnly {
			fmt.Fprintf(p.out, "\nℹ️  Broad approval unavailable: registrable domain is the same as host (%s)\n", hostLabel)
		}
		fmt.Fprintf(p.out, "\nStrictness scale: 0 = least restrictive, %d = most restrictive\n", maxChoice)
		for _, opt := range menu.Options {
			fmt.Fprintf(p.out, "%s) %s\n", p.strictChoice(opt.Index, maxChoice), opt.Label)
		}
		if p.apiKey != "" {
			fmt.Fprintf(p.out, "\n[D]iscuss\n")
			fmt.Fprintf(p.out, "Choose [%s/d]: ", choiceRange)
		} else {
			fmt.Fprintf(p.out, "\nChoose [%s]: ", choiceRange)
		}
		line, err := p.in.ReadString('\n')
		if err != nil {
			return PromptResult{Decision: Skipped}, err
		}
		input := normalizePromptInput(line)
		if input == "d" {
			if p.apiKey != "" {
				if err := p.discuss(denials, proposal); err != nil {
					fmt.Fprintf(p.out, "Discuss error: %v\n", err)
				}
				continue
			}
			fmt.Fprintf(p.out, "Invalid input. Enter %s.\n", choiceRange)
			continue
		}
		if result, ok := menu.selectByInput(input); ok {
			fmt.Fprintf(p.out, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			return result, nil
		}
		if p.apiKey != "" {
			fmt.Fprintf(p.out, "Invalid input. Enter %s or d.\n", choiceRange)
		} else {
			fmt.Fprintf(p.out, "Invalid input. Enter %s.\n", choiceRange)
		}
	}
}

func networkScopeExample(denials []audit.Record) (host, domain string) {
	for _, d := range denials {
		if d.Action != "http:Request" || d.Resource == "" {
			continue
		}
		host = netscope.NormalizeHost(d.Resource)
		if host == "" {
			continue
		}
		domain = netscope.EffectiveDomain(host)
		if domain == "" {
			domain = host
		}
		return host, domain
	}
	return "", ""
}
