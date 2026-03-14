package protector

import (
	"fmt"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/denial"
)

// Evaluate classifies and evaluates a command, returning the decision.
func (p *Protector) Evaluate(command string) Decision {
	start := time.Now()

	// Step 1: Classify the command
	cl := p.classifier.Classify(command)

	// Step 2: Handle pipe-to-shell and unmapped
	switch cl.Decision {
	case "deny_always":
		var msg denial.Message
		if strings.Contains(strings.ToLower(cl.Reason), "pipe-to-shell") {
			msg = denial.NewPipeToShellDenial(p.agent, command)
		} else {
			msg = denial.NewDangerousCommandDenial(p.agent, cl.Reason)
		}
		d := Decision{
			Result:    "deny",
			Path:      "pipe_to_shell",
			Reason:    cl.Reason,
			LatencyMs: time.Since(start).Milliseconds(),
			Denial:    &msg,
		}
		p.logDecision(command, d)
		return d

	case "deny_unmapped":
		executable := ""
		if len(cl.Segments) > 0 {
			executable = cl.Segments[0].Executable
		}
		msg := denial.NewUnmappedDenial(p.agent, executable)
		d := Decision{
			Result:    "deny",
			Path:      "unmapped",
			Reason:    cl.Reason,
			LatencyMs: time.Since(start).Milliseconds(),
			Denial:    &msg,
		}
		if len(cl.Segments) > 0 {
			d.Action = cl.Segments[0].Action
			d.Resource = cl.Segments[0].Resource
		}
		if d.Action == "" {
			d.Action = "exec:Run"
		}
		if d.Resource == "" {
			d.Resource = executable
		}
		p.logDecision(command, d)
		return d
	}

	// Ignore shell assignment/no-op classifications (no executable segments).
	// These are shell-internal bookkeeping lines and should not clutter audit/watch.
	if len(cl.Segments) == 0 {
		return Decision{
			Result:    "permit",
			Path:      "noop",
			Reason:    "no executable command",
			LatencyMs: time.Since(start).Milliseconds(),
		}
	}

	// Step 3: Evaluate each segment against Cedar
	// For compound commands, all segments must be permitted.
	for _, seg := range cl.Segments {
		principal := fmt.Sprintf(`Agent::"%s"`, CedarEscapeID(p.agent))
		action := fmt.Sprintf(`Action::"%s"`, CedarEscapeID(seg.Action))

		resource := seg.Resource
		if resource == "" {
			resource = "_"
		}
		resourceStr := fmt.Sprintf(`Resource::"%s"`, CedarEscapeID(resource))

		cedarDecision, err := p.cedar.Evaluate(CedarRequest{
			Principal: principal,
			Action:    action,
			Resource:  resourceStr,
		})

		if err != nil {
			d := Decision{
				Result:    "deny",
				Path:      "error",
				Action:    seg.Action,
				Resource:  seg.Resource,
				Reason:    fmt.Sprintf("Cedar evaluation error: %v", err),
				LatencyMs: time.Since(start).Milliseconds(),
			}
			p.logDecision(command, d)
			return d
		}

		if cedarDecision == CedarDeny {
			msg := denial.NewDenial(p.agent, seg.Action, seg.Resource,
				fmt.Sprintf("Cedar denied %s on %s", seg.Action, seg.Resource))
			d := Decision{
				Result:    "deny",
				Path:      "policy",
				Action:    seg.Action,
				Resource:  seg.Resource,
				Reason:    fmt.Sprintf("Cedar denied %s on %s", seg.Action, seg.Resource),
				LatencyMs: time.Since(start).Milliseconds(),
				Denial:    &msg,
			}
			p.logDecision(command, d)
			return d
		}
	}

	// All segments permitted
	action := ""
	resource := ""
	path := "policy"
	if len(cl.Segments) > 0 {
		action = cl.Segments[0].Action
		resource = cl.Segments[0].Resource
		// Check if it was permitted by always-allowed (fs:Read is always allowed in our test)
		// We can't distinguish easily from Cedar output, so we leave path as "policy"
		// The always-allowed.cedar IS a policy — it just has special provenance
	}

	d := Decision{
		Result:    "permit",
		Path:      path,
		Action:    action,
		Resource:  resource,
		LatencyMs: time.Since(start).Milliseconds(),
	}
	p.logDecision(command, d)
	return d
}
