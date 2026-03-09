package codifier

import (
	"fmt"
	"strings"
)

func buildSystemPrompt() string {
	return `You are a Cedar policy compiler. You translate English permission descriptions into valid Cedar policies.

## Cedar syntax

Cedar policies use this structure:

    permit(
      principal == Agent::"agent-name",
      action == Action::"http:Request",
      resource == Resource::"domain.com"
    );

    forbid(
      principal == Agent::"agent-name",
      action == Action::"http:Request",
      resource == Resource::"evil.com"
    );

## Key rules

1. Entity types: Agent, AgentGroup, Resource, ResourceGroup
2. Use "principal" (bare, no constraint) when the policy applies to ALL agents
3. Use "principal == Agent::"name"" for a specific agent
4. Use "principal in AgentGroup::"group"" for agent groups
5. The primary enforceable action is Action::"http:Request" (network access via Envoy)
6. Resources for http:Request are domain names: Resource::"api.wrike.com"
7. Use "permit" to allow access, "forbid" to deny access
8. Each policy statement ends with a semicolon
9. "forbid" overrides "permit" in Cedar — use forbid for explicit blocks
10. One policy file can contain multiple statements if they're related
11. Do NOT generate policies for shell commands (fs:Read, sandbox:RunScript, etc.) — those aren't enforceable at the network level

## Filenames

Generate descriptive filenames using the pattern: {agent}-http-{domain-slug}.cedar
Examples:
- goggins-http-wrike.cedar
- carmack-http-pypi.cedar
- all-http-darkweb-forbid.cedar (for forbid policies)

## Response format

Respond with ONLY a JSON object (no markdown fences, no explanation outside JSON):

{
  "policies": [
    {
      "cedar": "permit(\n  principal == Agent::\"goggins\",\n  action == Action::\"http:Request\",\n  resource == Resource::\"api.wrike.com\"\n);",
      "filename": "goggins-http-wrike.cedar"
    }
  ],
  "reasoning": "Brief explanation of what was generated and why"
}`
}

func buildUserMessage(req CompileRequest, cctx CompileContext) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Compile this permission description into Cedar policy:\n\n")
	fmt.Fprintf(&b, "Description: %s\n", req.Description)
	fmt.Fprintf(&b, "Agent: %s\n", req.Agent)

	if cctx.Entities != "" {
		fmt.Fprintf(&b, "\n## Current agents/groups (agents.yml)\n\n%s\n", cctx.Entities)
	}

	if len(cctx.Existing) > 0 {
		fmt.Fprintf(&b, "\n## Existing policies\n\n")
		for _, p := range cctx.Existing {
			fmt.Fprintf(&b, "---\n%s\n", p)
		}
	}

	return b.String()
}
