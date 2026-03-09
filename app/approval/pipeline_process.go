package approval

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/app/advocate"
	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/app/codifier"
	"github.com/marcusmom/land-of-agents/engine/config"
)

// Process takes a batch of denials and produces proposals with Cedar policies.
func (p *Pipeline) Process(ctx context.Context, denials []audit.Record) (*PipelineResult, error) {
	if len(denials) == 0 {
		return &PipelineResult{}, nil
	}

	var entities string
	var existingPerms []string
	kit, err := config.LoadKit(p.cfg.KitDir)
	if err == nil {
		entitiesPath := config.AgentRegistryPath(p.cfg.KitDir)
		if data, err := os.ReadFile(entitiesPath); err == nil {
			entities = string(data)
		}
		for _, pf := range kit.Policies {
			if data, err := os.ReadFile(pf); err == nil {
				existingPerms = append(existingPerms, string(data))
			}
		}
	}

	agent := denials[0].Agent
	if p.cfg.APIKey != "" {
		return p.processWithLLM(ctx, denials, agent, entities, existingPerms)
	}
	return p.processWithFallback(denials, agent)
}

func (p *Pipeline) processWithLLM(ctx context.Context, denials []audit.Record, agentName, entities string, existingPerms []string) (*PipelineResult, error) {
	adv := advocate.New(p.cfg.APIKey)
	proposals, err := adv.Propose(ctx, advocate.ProposalRequest{
		Denials:       denials,
		Agent:         agentName,
		ExistingPerms: existingPerms,
		Entities:      entities,
	})
	if err != nil {
		return p.processWithFallback(denials, agentName)
	}

	cod := codifier.New(p.cfg.APIKey)
	cctx := codifier.CompileContext{
		Entities: entities,
		Existing: existingPerms,
	}

	result := &PipelineResult{}
	for _, proposal := range proposals {
		compiled, err := cod.Compile(ctx, codifier.CompileRequest{
			Description: proposal.Description,
			Agent:       proposal.Agent,
		}, cctx)
		if err != nil {
			result.Proposals = append(result.Proposals, templateProposal(denials[0]))
			continue
		}
		for _, pol := range compiled.Policies {
			result.Proposals = append(result.Proposals, ProposalWithCedar{
				Description: proposal.Description,
				Reasoning:   proposal.Reasoning,
				Agent:       proposal.Agent,
				DenialIDs:   proposal.DenialIDs,
				Cedar:       pol.Cedar,
				Filename:    pol.Filename,
			})
		}
	}
	return result, nil
}

func (p *Pipeline) processWithFallback(denials []audit.Record, agentName string) (*PipelineResult, error) {
	proposals := advocate.ProposeFallback(denials)
	result := &PipelineResult{}
	for i, proposal := range proposals {
		d := denials[0]
		if i < len(denials) {
			d = denials[i]
		}
		result.Proposals = append(result.Proposals, ProposalWithCedar{
			Description: proposal.Description,
			Reasoning:   proposal.Reasoning,
			Agent:       proposal.Agent,
			DenialIDs:   proposal.DenialIDs,
			Cedar:       templateCedar(d),
			Filename:    templateFilename(d),
		})
	}
	return result, nil
}

func templateProposal(d audit.Record) ProposalWithCedar {
	return ProposalWithCedar{
		Description: codifier.DescriptionFromDenial(d.Agent, d.Action, d.Resource),
		Reasoning:   "Generated from denied activity (LLM assist is off). Choose host or domain scope before approving.",
		Agent:       d.Agent,
		DenialIDs:   []string{d.ID},
		Cedar:       templateCedar(d),
		Filename:    templateFilename(d),
	}
}

func templateCedar(d audit.Record) string {
	return fmt.Sprintf(`permit(
  principal == Agent::"%s",
  action == Action::"%s",
  resource == Resource::"%s"
);
`, d.Agent, d.Action, d.Resource)
}

func templateFilename(d audit.Record) string {
	safe := strings.NewReplacer(
		":", "-", "/", "-", ".", "-", " ", "-",
	).Replace(fmt.Sprintf("%s-%s-%s", d.Agent, d.Action, d.Resource))
	return safe + ".cedar"
}
