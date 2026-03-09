// Package denial formats structured denial messages for blocked actions.
package denial

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Message is a structured denial that can be returned to the agent.
type Message struct {
	LOADenial      bool   `json:"loa_denial"`
	Agent          string `json:"agent"`
	Action         string `json:"action"`
	Resource       string `json:"resource"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	PermissionRef  string `json:"permission_ref,omitempty"`
	PermissionName string `json:"permission_name,omitempty"`
	PolicyRef      string `json:"policy_ref,omitempty"`
	Suggestion     string `json:"suggestion"`
	AuditID        string `json:"audit_id,omitempty"`
}

// Format returns the denial as a human-readable string for the agent.
func (m Message) Format() string {
	var b strings.Builder

	// Header
	b.WriteString("Permission Denied\n")

	// Agent name
	agentDisplay := cases.Title(language.English).String(m.Agent)
	fmt.Fprintf(&b, "Agent: %s\n", agentDisplay)

	// Attempted request
	if m.Action != "" || m.Resource != "" {
		action := m.Action
		if action == "" {
			action = "(unspecified action)"
		}
		resource := m.Resource
		if resource == "" {
			resource = "(unspecified resource)"
		}
		fmt.Fprintf(&b, "Request: %s -> %s\n", action, resource)
	}

	// Reason
	if m.Reason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", m.Reason)
	}

	// Policy reference
	if m.PermissionName != "" && m.PermissionRef != "" {
		fmt.Fprintf(&b, "Policy: %s (%s)\n", m.PermissionName, m.PermissionRef)
	} else if m.PermissionRef != "" {
		fmt.Fprintf(&b, "Policy: %s\n", m.PermissionRef)
	}

	// Suggested next step
	if m.Suggestion != "" {
		fmt.Fprintf(&b, "Next step: %s\n", m.Suggestion)
	}

	// Audit reference
	if m.AuditID != "" {
		fmt.Fprintf(&b, "Audit ID: %s\n", m.AuditID)
	}

	return b.String()
}

// JSON returns the denial as a JSON string for structured consumption.
func (m Message) JSON() string {
	data, _ := json.Marshal(m)
	return string(data)
}

// NewDenial creates a denial message for a blocked action.
func NewDenial(agent, action, resource, reason string) Message {
	return Message{
		LOADenial:  true,
		Agent:      agent,
		Action:     action,
		Resource:   resource,
		Decision:   "deny",
		Reason:     reason,
		Suggestion: "This action is blocked. Continue with other work or ask the user for help.",
	}
}

// NewUnmappedDenial creates a denial for an unknown command.
func NewUnmappedDenial(agent, executable string) Message {
	return Message{
		LOADenial:  true,
		Agent:      agent,
		Action:     "",
		Resource:   "",
		Decision:   "deny",
		Reason:     fmt.Sprintf("Unknown command %q is not recognized by the governance system.", executable),
		Suggestion: "This action is blocked. Continue with other work or ask the user for help.",
	}
}

// NewPipeToShellDenial creates a denial for a pipe-to-shell pattern.
func NewPipeToShellDenial(agent, command string) Message {
	return Message{
		LOADenial:  true,
		Agent:      agent,
		Action:     "",
		Resource:   "",
		Decision:   "deny",
		Reason:     "Pipe-to-shell pattern detected. This is always blocked for security.",
		Suggestion: "This action is blocked. Continue with other work or ask the user for help.",
	}
}

// NewDangerousCommandDenial creates a denial for strict-mode dangerous command chains.
func NewDangerousCommandDenial(agent, reason string) Message {
	if strings.TrimSpace(reason) == "" {
		reason = "Dangerous command chain detected. This is blocked for security."
	}
	return Message{
		LOADenial:  true,
		Agent:      agent,
		Action:     "",
		Resource:   "",
		Decision:   "deny",
		Reason:     reason,
		Suggestion: "This action is blocked. Continue with other work or ask the user for help.",
	}
}
