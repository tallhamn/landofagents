package main

import (
	"fmt"

	"github.com/marcusmom/land-of-agents/app/approval"
)

func applyPolicy(pipeline *approval.Pipeline, prop approval.ProposalWithCedar) (string, error) {
	activePath, err := pipeline.WriteActivePolicy(prop)
	if err != nil {
		return "", fmt.Errorf("activate policy: %w", err)
	}
	return activePath, nil
}
