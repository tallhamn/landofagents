package protector

import "github.com/marcusmom/land-of-agents/engine/audit"

func (p *Protector) logDecision(command string, d Decision) {
	if p.logger == nil {
		return
	}
	context := map[string]any{
		"command": command,
	}
	p.logger.Log(audit.Record{
		Agent:        p.agent,
		Scope:        p.scope,
		Action:       d.Action,
		Resource:     d.Resource,
		Decision:     d.Result,
		DecisionPath: d.Path,
		PolicyRef:    d.PolicyRef,
		Context:      context,
		LatencyMs:    d.LatencyMs,
		DenialReason: d.Reason,
	})
}
