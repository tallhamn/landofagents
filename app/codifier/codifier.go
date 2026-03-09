// Package codifier compiles English permission descriptions into Cedar policies using an LLM.
package codifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// CompileRequest is the English description to compile into Cedar.
type CompileRequest struct {
	Description string // e.g. "goggins can access api.wrike.com"
	Agent       string // e.g. "goggins"
}

// CompileContext provides the current state of the permission kit.
type CompileContext struct {
	Entities string   // agents.yml content (for agent/group names)
	Existing []string // existing Cedar policy contents
}

// CompileResult is the output of a successful compilation.
type CompileResult struct {
	Policies  []Policy
	Reasoning string
}

// Policy is a single Cedar policy with its suggested filename.
type Policy struct {
	Cedar    string // valid Cedar text
	Filename string // e.g. "goggins-http-wrike.cedar"
}

// Codifier compiles English to Cedar via the Anthropic API.
type Codifier struct {
	client *anthropic.Client
	model  anthropic.Model
}

// New creates a Codifier using the given API key.
func New(apiKey string) *Codifier {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &Codifier{
		client: &client,
		model:  anthropic.ModelClaudeSonnet4_20250514,
	}
}

// Compile sends the English description to the LLM and returns validated Cedar policies.
func (c *Codifier) Compile(ctx context.Context, req CompileRequest, cctx CompileContext) (*CompileResult, error) {
	systemPrompt := buildSystemPrompt()
	userMessage := buildUserMessage(req, cctx)

	resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     c.model,
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

	// Extract text from response
	var text string
	for _, block := range resp.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}
	if text == "" {
		return nil, fmt.Errorf("empty response from LLM")
	}

	result, err := parseResponse(text)
	if err != nil {
		return nil, fmt.Errorf("parse LLM response: %w", err)
	}

	// Validate each policy parses as Cedar
	for i, p := range result.Policies {
		if err := ValidateCedar(p.Cedar); err != nil {
			return nil, fmt.Errorf("policy %d (%s) invalid Cedar: %w", i, p.Filename, err)
		}
	}

	return result, nil
}

// DescriptionFromDenial builds an English description from a denial's fields.
func DescriptionFromDenial(agent, action, resource string) string {
	// Map Cedar action names to human-readable descriptions
	verb := "perform " + action + " on"
	switch {
	case strings.HasPrefix(action, "http:"):
		verb = "make HTTP requests to"
	case strings.HasPrefix(action, "email:"):
		verb = "send emails to"
	case strings.HasPrefix(action, "fs:"):
		verb = action[3:] // "Read", "Write", etc.
	}
	return fmt.Sprintf("%s can %s %s", agent, verb, resource)
}

// llmResponse is the expected JSON structure from the LLM.
type llmResponse struct {
	Policies []struct {
		Cedar    string `json:"cedar"`
		Filename string `json:"filename"`
	} `json:"policies"`
	Reasoning string `json:"reasoning"`
}

// parseResponse extracts policies from the LLM's JSON response.
func parseResponse(text string) (*CompileResult, error) {
	// The LLM may wrap JSON in markdown code fences — strip them
	cleaned := stripCodeFence(text)

	var resp llmResponse
	if err := json.Unmarshal([]byte(cleaned), &resp); err != nil {
		return nil, fmt.Errorf("unmarshal JSON: %w (raw: %s)", err, truncate(text, 200))
	}

	if len(resp.Policies) == 0 {
		return nil, fmt.Errorf("no policies in response")
	}

	result := &CompileResult{Reasoning: resp.Reasoning}
	for _, p := range resp.Policies {
		if p.Cedar == "" {
			return nil, fmt.Errorf("empty cedar in policy %q", p.Filename)
		}
		result.Policies = append(result.Policies, Policy{
			Cedar:    p.Cedar,
			Filename: p.Filename,
		})
	}
	return result, nil
}

// stripCodeFence removes markdown ```json ... ``` wrapping if present.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// Remove opening fence line
		if idx := strings.Index(s, "\n"); idx != -1 {
			s = s[idx+1:]
		}
		// Remove closing fence
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
