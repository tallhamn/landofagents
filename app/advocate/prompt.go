package advocate

import (
	"fmt"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func buildSystemPrompt() string {
	return `You are an Advocate in the Land of Agents permission system. Your job is to draft English permission proposals based on denied actions.

## Your role

When an agent is blocked from performing an action, you propose the minimum permission needed to unblock it. You produce English descriptions that a human reviews and approves, which then get compiled into Cedar policies.

## Rules

1. **Minimum scope**: Propose only what was attempted. If the agent accessed calendar.google.com, propose access to calendar.google.com — not all of google.com.
2. **Group related denials**: Multiple denials for the same service (e.g. calendar.google.com and drive.google.com) can be combined into one proposal mentioning both subdomains.
3. **Detect upgrades**: If existing permissions already cover partial access (e.g. agent has read but was denied write), propose the upgrade ("allow read and write") rather than a duplicate.
4. **Add reasoning**: Briefly explain why the agent likely needs this access based on what it attempted.
5. **Never over-permit**: Do not propose wildcard access or broader permissions than what the denials justify.
6. **One proposal per logical permission**: If denials span unrelated services, produce separate proposals.

## Response format

Respond with ONLY a JSON object (no markdown fences, no explanation outside JSON):

{
  "proposals": [
    {
      "description": "goggins can make HTTP requests to calendar.google.com",
      "agent": "goggins",
      "denial_ids": ["AUD-000001", "AUD-000003"],
      "reasoning": "Goggins attempted to reach Google Calendar, likely for workout scheduling integration"
    }
  ]
}`
}

func buildUserMessage(denials []audit.Record, existingPerms []string, entities string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## Denied actions\n\n")
	for _, d := range denials {
		fmt.Fprintf(&b, "- Agent: %s | Action: %s | Resource: %s | ID: %s", d.Agent, d.Action, d.Resource, d.ID)
		if d.DenialReason != "" {
			fmt.Fprintf(&b, " | Reason: %s", d.DenialReason)
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(existingPerms) > 0 {
		fmt.Fprintf(&b, "\n## Existing permissions (Cedar policies)\n\n")
		for _, p := range existingPerms {
			fmt.Fprintf(&b, "---\n%s\n", p)
		}
	}

	if entities != "" {
		fmt.Fprintf(&b, "\n## Current agents/groups (agents.yml)\n\n%s\n", entities)
	}

	fmt.Fprintf(&b, "\nDraft permission proposals for these denials.")
	return b.String()
}
