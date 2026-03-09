package approval

import "fmt"

type networkDecisionOption struct {
	Index  int
	Label  string
	Result PromptResult
}

type networkDecisionMenu struct {
	HostOnly bool
	Options  []networkDecisionOption
}

func buildNetworkDecisionMenu(agentShort, hostLabel, domainLabel string, hostOnly bool) networkDecisionMenu {
	if hostOnly {
		return networkDecisionMenu{
			HostOnly: true,
			Options: []networkDecisionOption{
				{
					Index: 0,
					Label: fmt.Sprintf("all agents allowed %s", hostLabel),
					Result: PromptResult{
						Decision:     Approved,
						Scope:        AllAgents,
						NetworkScope: NetworkScopeHost,
						Effect:       PolicyPermit,
					},
				},
				{
					Index: 1,
					Label: fmt.Sprintf("%s allowed %s", agentShort, hostLabel),
					Result: PromptResult{
						Decision:     Approved,
						Scope:        AgentOnly,
						NetworkScope: NetworkScopeHost,
						Effect:       PolicyPermit,
					},
				},
				{
					Index: 2,
					Label: "allow once (this request)",
					Result: PromptResult{
						Decision:     AllowedOnce,
						Scope:        AgentOnly,
						NetworkScope: NetworkScopeHost,
						Effect:       PolicyPermit,
					},
				},
				{
					Index: 3,
					Label: "block once (this request)",
					Result: PromptResult{
						Decision:     BlockedOnce,
						Scope:        AgentOnly,
						NetworkScope: NetworkScopeHost,
						Effect:       PolicyForbid,
					},
				},
				{
					Index: 4,
					Label: fmt.Sprintf("%s blocked %s", agentShort, hostLabel),
					Result: PromptResult{
						Decision:     Approved,
						Scope:        AgentOnly,
						NetworkScope: NetworkScopeHost,
						Effect:       PolicyForbid,
					},
				},
				{
					Index: 5,
					Label: fmt.Sprintf("all agents blocked %s", hostLabel),
					Result: PromptResult{
						Decision:     Approved,
						Scope:        AllAgents,
						NetworkScope: NetworkScopeHost,
						Effect:       PolicyForbid,
					},
				},
			},
		}
	}

	return networkDecisionMenu{
		HostOnly: false,
		Options: []networkDecisionOption{
			{
				Index: 0,
				Label: fmt.Sprintf("all agents allowed %s", domainLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AllAgents,
					NetworkScope: NetworkScopeDomain,
					Effect:       PolicyPermit,
				},
			},
			{
				Index: 1,
				Label: fmt.Sprintf("all agents allowed %s", hostLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AllAgents,
					NetworkScope: NetworkScopeHost,
					Effect:       PolicyPermit,
				},
			},
			{
				Index: 2,
				Label: fmt.Sprintf("%s allowed %s", agentShort, domainLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AgentOnly,
					NetworkScope: NetworkScopeDomain,
					Effect:       PolicyPermit,
				},
			},
			{
				Index: 3,
				Label: fmt.Sprintf("%s allowed %s", agentShort, hostLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AgentOnly,
					NetworkScope: NetworkScopeHost,
					Effect:       PolicyPermit,
				},
			},
			{
				Index: 4,
				Label: "allow once (this request)",
				Result: PromptResult{
					Decision:     AllowedOnce,
					Scope:        AgentOnly,
					NetworkScope: NetworkScopeHost,
					Effect:       PolicyPermit,
				},
			},
			{
				Index: 5,
				Label: "block once (this request)",
				Result: PromptResult{
					Decision:     BlockedOnce,
					Scope:        AgentOnly,
					NetworkScope: NetworkScopeHost,
					Effect:       PolicyForbid,
				},
			},
			{
				Index: 6,
				Label: fmt.Sprintf("%s blocked %s", agentShort, hostLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AgentOnly,
					NetworkScope: NetworkScopeHost,
					Effect:       PolicyForbid,
				},
			},
			{
				Index: 7,
				Label: fmt.Sprintf("%s blocked %s", agentShort, domainLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AgentOnly,
					NetworkScope: NetworkScopeDomain,
					Effect:       PolicyForbid,
				},
			},
			{
				Index: 8,
				Label: fmt.Sprintf("all agents blocked %s", hostLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AllAgents,
					NetworkScope: NetworkScopeHost,
					Effect:       PolicyForbid,
				},
			},
			{
				Index: 9,
				Label: fmt.Sprintf("all agents blocked %s", domainLabel),
				Result: PromptResult{
					Decision:     Approved,
					Scope:        AllAgents,
					NetworkScope: NetworkScopeDomain,
					Effect:       PolicyForbid,
				},
			},
		},
	}
}

func (m networkDecisionMenu) maxIndex() int {
	if len(m.Options) == 0 {
		return 0
	}
	return m.Options[len(m.Options)-1].Index
}

func (m networkDecisionMenu) selectByInput(input string) (PromptResult, bool) {
	for _, opt := range m.Options {
		if input == fmt.Sprintf("%d", opt.Index) {
			return opt.Result, true
		}
	}
	return PromptResult{}, false
}
