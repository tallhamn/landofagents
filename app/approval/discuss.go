package approval

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/marcusmom/land-of-agents/engine/audit"
)

// discuss reads a question from stdin, sends it to the LLM with denial context,
// and prints the answer. Also shows Cedar details so the user can inspect them.
func (p *Prompter) discuss(denials []audit.Record, proposal ProposalWithCedar) error {
	fmt.Fprintf(p.out, "Question: ")
	question, err := p.in.ReadString('\n')
	if err != nil {
		return err
	}
	question = strings.TrimSpace(question)
	if question == "" {
		return nil
	}

	// Build context for the LLM
	var sb strings.Builder
	sb.WriteString("You are helping a user review an agent permission request in Land of Agents (LOA).\n\n")
	sb.WriteString("Context:\n")
	fmt.Fprintf(&sb, "Agent: %s\n", proposal.Agent)
	for _, d := range denials {
		fmt.Fprintf(&sb, "Denied action: %s → %s\n", d.Action, d.Resource)
	}
	fmt.Fprintf(&sb, "\nProposed permission: %s\n", proposal.Description)
	if proposal.Reasoning != "" {
		fmt.Fprintf(&sb, "Reasoning: %s\n", proposal.Reasoning)
	}
	fmt.Fprintf(&sb, "\nCedar policy:\n%s\n", strings.TrimSpace(proposal.Cedar))
	fmt.Fprintf(&sb, "Target file: policies/active/%s\n", proposal.Filename)
	fmt.Fprintf(&sb, "\nUser question: %s\n", question)
	sb.WriteString("\nAnswer concisely (2-4 sentences). Focus on security implications and what the resource/domain is.")

	client := anthropic.NewClient(option.WithAPIKey(p.apiKey))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.ModelClaudeHaiku4_5_20251001,
		MaxTokens: 512,
		Messages: []anthropic.MessageParam{
			{
				Role: anthropic.MessageParamRoleUser,
				Content: []anthropic.ContentBlockParamUnion{
					anthropic.NewTextBlock(sb.String()),
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("LLM call failed: %w", err)
	}

	var answer string
	for _, block := range resp.Content {
		if block.Type == "text" {
			answer += block.Text
		}
	}

	fmt.Fprintf(p.out, "\n")
	// Indent each line of the answer
	for _, line := range strings.Split(strings.TrimSpace(answer), "\n") {
		fmt.Fprintf(p.out, "  %s\n", line)
	}

	// Show Cedar details so user can inspect
	fmt.Fprintf(p.out, "\nDetails:\n")
	for _, line := range strings.Split(strings.TrimSpace(proposal.Cedar), "\n") {
		fmt.Fprintf(p.out, "  %s\n", line)
	}
	fmt.Fprintf(p.out, "  → policies/active/%s\n", proposal.Filename)

	return nil
}
