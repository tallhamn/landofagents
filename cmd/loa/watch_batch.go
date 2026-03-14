package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/oneshot"
)

// handleBatch processes a batch of denials through the approval pipeline.
// Returns the denial records that were approved, so the caller can suppress
// stale re-denials for the same resources.
func handleBatch(ctx context.Context, pipeline *approval.Pipeline, kitDir, apiKey string, denials []audit.Record) []audit.Record {
	actionable := filterActionableBatch(kitDir, denials)
	if len(actionable) == 0 {
		return nil
	}

	result, err := pipeline.Process(ctx, actionable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pipeline error: %v\n", err)
		return nil
	}

	var approved []audit.Record
	for _, prop := range result.Proposals {
		covered := coveredDenialsForProposal(prop, actionable)
		if len(covered) == 0 {
			covered = actionable
		}

		prompter := approval.NewPrompter(os.Stdin, os.Stderr, approval.PrompterOpts{
			APIKey:    apiKey,
			AgentName: prop.Agent,
		})
		promptResult, err := prompter.ShowAndAsk(prop, covered)
		if err != nil {
			if err == io.EOF {
				return approved
			}
			fmt.Fprintf(os.Stderr, "Prompt error: %v\n", err)
			continue
		}
		handlePromptDecision(pipeline, kitDir, prop, covered, promptResult)
		if promptResult.Decision == approval.Approved {
			approved = append(approved, covered...)
		}
	}
	return approved
}

func filterActionableBatch(kitDir string, denials []audit.Record) []audit.Record {
	var actionable []audit.Record
	for _, d := range denials {
		if isUnmappedDeniedRecord(d) {
			reportUnmappedDetection(d)
			continue
		}
		actionable = append(actionable, d)
	}
	return handleFilesystemDenials(kitDir, actionable)
}

func coveredDenialsForProposal(prop approval.ProposalWithCedar, actionable []audit.Record) []audit.Record {
	idSet := map[string]bool{}
	for _, id := range prop.DenialIDs {
		idSet[id] = true
	}
	var covered []audit.Record
	for _, d := range actionable {
		if idSet[d.ID] {
			covered = append(covered, d)
		}
	}
	return covered
}

func reportUnmappedDetection(d audit.Record) {
	cmd := ""
	if d.Context != nil {
		if raw, ok := d.Context["command"]; ok {
			cmd = fmt.Sprintf("%v", raw)
		}
	}
	fmt.Fprintf(os.Stderr, "Detection: %s (no policy mapping)\n", d.DecisionPath)
	if cmd != "" {
		fmt.Fprintf(os.Stderr, "  Command: %s\n", cmd)
	}
	if d.DenialReason != "" {
		fmt.Fprintf(os.Stderr, "  Reason:  %s\n", d.DenialReason)
	}
}

func handlePromptDecision(pipeline *approval.Pipeline, kitDir string, prop approval.ProposalWithCedar, covered []audit.Record, result approval.PromptResult) {
	switch result.Decision {
	case approval.Approved:
		fmt.Fprintf(os.Stderr, "Applying saved policy...\n")
		msg, err := activateApprovedProposal(pipeline, prop, covered, result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error applying approval: %v\n", err)
			return
		}
		fmt.Fprintln(os.Stderr, msg)
	case approval.AllowedOnce, approval.BlockedOnce:
		handleOneTimeDecision(kitDir, prop, covered, result)
	case approval.Rejected:
		fmt.Fprintf(os.Stderr, "🔴 Rejected (no policy change).\n")
	case approval.Skipped:
		fmt.Fprintf(os.Stderr, "⏸️  Deferred (no policy change).\n")
	}
}


func activateApprovedProposal(pipeline *approval.Pipeline, prop approval.ProposalWithCedar, covered []audit.Record, result approval.PromptResult) (string, error) {
	prop = applyNetworkScope(prop, covered, result.NetworkScope)
	if result.Scope == approval.AllAgents {
		prop = rewriteForAllAgents(prop)
	}
	if result.Effect == approval.PolicyForbid {
		prop = rewriteForbidPolicy(prop)
	}

	activePath, err := applyPolicy(pipeline, prop)
	if err != nil {
		return "", err
	}

	scopeLabel := prop.Agent + " only"
	if result.Scope == approval.AllAgents {
		scopeLabel = "all agents"
	}
	activeFile := filepath.Base(activePath)
	if result.Effect == approval.PolicyForbid {
		return fmt.Sprintf("🔴 Block policy active for %s → %s", scopeLabel, activeFile), nil
	}
	return fmt.Sprintf("🟢 Approved for %s → %s", scopeLabel, activeFile), nil
}


func handleOneTimeDecision(kitDir string, prop approval.ProposalWithCedar, covered []audit.Record, result approval.PromptResult) {
	oneshoot := oneshot.EffectAllow
	verb := "Allowed once"
	icon := "🟢"
	if result.Decision == approval.BlockedOnce {
		oneshoot = oneshot.EffectDeny
		verb = "Blocked once"
		icon = "🔴"
	}

	added := 0
	for _, d := range covered {
		if strings.TrimSpace(d.Action) == "" || strings.TrimSpace(d.Resource) == "" {
			continue
		}
		agentName := d.Agent
		if strings.TrimSpace(agentName) == "" {
			agentName = prop.Agent
		}
		if _, err := oneshot.Add(kitDir, oneshot.Decision{
			Agent:    agentName,
			Action:   d.Action,
			Resource: d.Resource,
			RunID:    recordRunID(d),
			Effect:   oneshoot,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Error queuing one-time decision: %v\n", err)
			continue
		}
		added++
	}
	if added == 0 {
		fmt.Fprintf(os.Stderr, "No matching requests to apply one-time decision.\n")
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s%s (%d request%s).\n", icon, verb, oneTimeScopeLabel(covered), added, pluralSuffix(added))
}

func recordRunID(r audit.Record) string {
	if r.Context == nil {
		return ""
	}
	raw, ok := r.Context["run_id"]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", raw))
}

func oneTimeScopeLabel(records []audit.Record) string {
	var runID string
	for _, r := range records {
		cur := recordRunID(r)
		if strings.TrimSpace(cur) == "" {
			return ""
		}
		if runID == "" {
			runID = cur
			continue
		}
		if runID != cur {
			return " for matching runs"
		}
	}
	if runID == "" {
		return ""
	}
	return " for this run"
}
