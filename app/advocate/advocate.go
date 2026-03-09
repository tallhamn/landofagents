package advocate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/app/codifier"
)

// ProposalRequest is the input to Propose: denial(s) + context.
type ProposalRequest struct {
	Denials       []audit.Record
	Agent         string
	ExistingPerms []string // existing .cedar file contents
	Entities      string   // agents.yml content
}

// Proposal is the output: one English description per logical permission needed.
type Proposal struct {
	Description string   // feeds into codifier.CompileRequest.Description
	Agent       string   // feeds into codifier.CompileRequest.Agent
	DenialIDs   []string // audit IDs this covers
	Reasoning   string   // why (for human review)
}

// Advocate drafts English permission proposals from denials via the Anthropic API.
type Advocate struct {
	client *anthropic.Client
	model  anthropic.Model
}

// New creates an Advocate using the given API key.
func New(apiKey string) *Advocate {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &Advocate{
		client: &client,
		model:  anthropic.ModelClaudeSonnet4_20250514,
	}
}

// Propose sends denial(s) to the LLM and returns English permission proposals.
func (a *Advocate) Propose(ctx context.Context, req ProposalRequest) ([]Proposal, error) {
	systemPrompt := buildSystemPrompt()
	userMessage := buildUserMessage(req.Denials, req.ExistingPerms, req.Entities)

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: 2048,
		System: []anthropic.TextBlockParam{
			{Type: "text", Text: systemPrompt},
		},
		Messages: []anthropic.MessageParam{
			{
				Role: anthropic.MessageParamRoleUser,
				Content: []anthropic.ContentBlockParamUnion{
					anthropic.NewTextBlock(userMessage),
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("anthropic API: %w", err)
	}

	var text string
	for _, block := range resp.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}
	if text == "" {
		return nil, fmt.Errorf("empty response from LLM")
	}

	proposals, err := parseResponse(text)
	if err != nil {
		return nil, fmt.Errorf("parse LLM response: %w", err)
	}

	// Fill in agent from request if the LLM omitted it
	for i := range proposals {
		if proposals[i].Agent == "" {
			proposals[i].Agent = req.Agent
		}
	}

	return proposals, nil
}

// ProposeFallback produces proposals without an LLM, using codifier.DescriptionFromDenial.
// Used when no API key is available.
func ProposeFallback(denials []audit.Record) []Proposal {
	proposals := make([]Proposal, 0, len(denials))
	for _, d := range denials {
		proposals = append(proposals, Proposal{
			Description: codifier.DescriptionFromDenial(d.Agent, d.Action, d.Resource),
			Agent:       d.Agent,
			DenialIDs:   []string{d.ID},
			Reasoning:   "Generated from denied activity (LLM assist is off). Choose host or domain scope before approving.",
		})
	}
	return proposals
}

// llmResponse is the expected JSON structure from the Advocate LLM.
type llmResponse struct {
	Proposals []struct {
		Description string   `json:"description"`
		Agent       string   `json:"agent"`
		DenialIDs   []string `json:"denial_ids"`
		Reasoning   string   `json:"reasoning"`
	} `json:"proposals"`
}

// parseResponse extracts proposals from the LLM's JSON response.
func parseResponse(text string) ([]Proposal, error) {
	cleaned := stripCodeFence(text)

	var resp llmResponse
	if err := json.Unmarshal([]byte(cleaned), &resp); err != nil {
		return nil, fmt.Errorf("unmarshal JSON: %w (raw: %s)", err, truncate(text, 200))
	}

	if len(resp.Proposals) == 0 {
		return nil, fmt.Errorf("no proposals in response")
	}

	proposals := make([]Proposal, 0, len(resp.Proposals))
	for _, p := range resp.Proposals {
		if p.Description == "" {
			return nil, fmt.Errorf("empty description in proposal")
		}
		proposals = append(proposals, Proposal{
			Description: p.Description,
			Agent:       p.Agent,
			DenialIDs:   p.DenialIDs,
			Reasoning:   p.Reasoning,
		})
	}
	return proposals, nil
}

// stripCodeFence removes markdown ```json ... ``` wrapping if present.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if idx := strings.Index(s, "\n"); idx != -1 {
			s = s[idx+1:]
		}
		if idx := strings.LastIndex(s, "```"); idx != -1 {
			s = s[:idx]
		}
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
