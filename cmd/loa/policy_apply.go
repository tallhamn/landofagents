package main

import (
	"fmt"

	"github.com/marcusmom/land-of-agents/app/approval"
)

type policyApplyResult struct {
	StagedPath string
	ActivePath string
}

func stageAndMaybeActivatePolicy(pipeline *approval.Pipeline, prop approval.ProposalWithCedar, activateNow bool) (policyApplyResult, error) {
	stagedPath, err := pipeline.StagePolicy(prop)
	if err != nil {
		return policyApplyResult{}, fmt.Errorf("stage policy: %w", err)
	}
	res := policyApplyResult{StagedPath: stagedPath}
	if !activateNow {
		return res, nil
	}
	activePath, err := pipeline.ActivatePolicy(stagedPath)
	if err != nil {
		return policyApplyResult{}, fmt.Errorf("activate policy: %w", err)
	}
	res.ActivePath = activePath
	return res, nil
}
