package approval

import (
	"bufio"
	"io"
)

// Decision is the user's choice: approve, reject, or skip.
type Decision int

const (
	Approved Decision = iota
	Rejected
	Skipped
	AllowedOnce
	BlockedOnce
)

// Scope controls whether the permission applies to one agent or all agents.
type Scope int

const (
	AgentOnly Scope = iota
	AllAgents
)

// NetworkScope controls how far a network permission should apply.
type NetworkScope int

const (
	NetworkScopeHost NetworkScope = iota
	NetworkScopeDomain
)

// PolicyEffect controls whether the generated policy should permit or forbid.
type PolicyEffect int

const (
	PolicyPermit PolicyEffect = iota
	PolicyForbid
)

// PromptResult is the user's response to an approval prompt.
type PromptResult struct {
	Decision     Decision
	Scope        Scope
	NetworkScope NetworkScope
	Effect       PolicyEffect
}

// PrompterOpts configures optional Prompter features.
type PrompterOpts struct {
	APIKey    string // enables discuss feature when non-empty
	AgentName string // for scope prompt label
}

// Prompter shows approval prompts and reads user responses.
type Prompter struct {
	in        *bufio.Reader
	out       io.Writer
	apiKey    string
	agentName string
	useColor  bool
}

// NewPrompter creates a prompter that reads from in and writes to out.
func NewPrompter(in io.Reader, out io.Writer, opts PrompterOpts) *Prompter {
	return &Prompter{
		in:        bufio.NewReader(in),
		out:       out,
		apiKey:    opts.APIKey,
		agentName: opts.AgentName,
		useColor:  supportsANSI(out),
	}
}
