package approval

import (
	"fmt"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

// ShowAndAsk displays the proposal and asks the user to approve, reject, or skip.
func (p *Prompter) ShowAndAsk(proposal ProposalWithCedar, denials []audit.Record) (PromptResult, error) {
	fmt.Fprintf(p.out, "\n━━━ LOA: Permission Request ━━━\n\n")

	networkMenu := shouldAskNetworkScope(denials)
	if networkMenu {
		p.renderNetworkHeader(proposal, denials)
	} else {
		p.renderStandardHeader(proposal, denials)
	}

	if networkMenu {
		return p.askNetworkDecision(proposal, denials)
	}
	return p.askStandardDecision(proposal, denials)
}

func (p *Prompter) renderNetworkHeader(proposal ProposalWithCedar, denials []audit.Record) {
	agent := strings.TrimSpace(proposal.Agent)
	if agent == "" {
		agent = p.agentName
	}
	if agent == "" {
		agent = "agent"
	}
	if len(denials) == 0 {
		return
	}
	d := denials[0]
	ts := promptTimestamp(d.Timestamp)
	fmt.Fprintf(p.out, "🤖 %s wants to access %s  [%s]\n", agent, p.blue(d.Resource), ts)
	if len(denials) > 1 {
		fmt.Fprintf(p.out, "   + %d more blocked request%s in this batch\n", len(denials)-1, pluralWord(len(denials)-1))
	}
}

func (p *Prompter) renderStandardHeader(proposal ProposalWithCedar, denials []audit.Record) {
	fmt.Fprintf(p.out, "🤖 Agent: %s\n", proposal.Agent)
	for _, d := range denials {
		ts := promptTimestamp(d.Timestamp)
		fmt.Fprintf(p.out, "⏸️  Denied: %s → %s  [%s]\n", d.Action, p.blue(d.Resource), ts)
	}
	if hasFSDenial(denials) {
		fmt.Fprintf(p.out, "Hint: if this path should be accessible, mount the directory (read-only or read-write) and retry.\n")
	}

	fmt.Fprintf(p.out, "\nPermission Request: %s\n", p.blueURLs(proposal.Description))
	if proposal.Reasoning != "" {
		fmt.Fprintf(p.out, "Reasoning: %s\n", proposal.Reasoning)
	}
	if policy := FormatCedarForDisplay(proposal.Cedar, p.out); policy != "" {
		fmt.Fprintf(p.out, "\nPolicy Preview:\n%s\n", indentLines(p.blueURLs(policy), "  "))
	}
}

func promptTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return time.Now().Local().Format("15:04:05")
	}
	return ts.Local().Format("15:04:05")
}
