package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/marcusmom/land-of-agents/app/adapters/openclaw"
	gapcontrol "github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/services/loaauthority"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

func workerAuthorityService() (*loaauthority.Service, bool) {
	svc, err := loaauthority.New(kitDir(), worker.WithLaunchValidator(openclaw.StrictValidator{}))
	if err != nil {
		return nil, false
	}
	return svc, true
}

func workerLaunchToControlSpawn(req worker.LaunchRequest) gapcontrol.SpawnRequest {
	out := gapcontrol.SpawnRequest{
		Version:        gapcontrol.VersionV1,
		RequestID:      fmt.Sprintf("req_worker_launch_%d", os.Getpid()),
		AgentID:        strings.TrimSpace(req.Agent),
		SessionID:      strings.TrimSpace(req.SessionID),
		WorkloadID:     strings.TrimSpace(req.WorkloadID),
		ParentWorkerID: strings.TrimSpace(req.ParentWorkerID),
		Runtime:        strings.TrimSpace(req.Runtime),
		Labels:         req.Labels,
	}
	out.MountProfile.Volumes = append([]string{}, req.MountProfile.Volumes...)
	out.NetworkProfile.Mode = strings.TrimSpace(req.NetworkProfile.Mode)
	out.NetworkProfile.InitialPolicyScope = strings.TrimSpace(req.NetworkProfile.InitialPolicyScope)
	out.SecretsProfile.Refs = append([]string{}, req.SecretsProfile.Refs...)
	out.SecretsProfile.Exposure = strings.TrimSpace(req.SecretsProfile.Exposure)
	return out
}

func isControlUnauthenticated(err error) bool {
	apiErr, ok := err.(*gapcontrol.APIError)
	return ok && apiErr != nil && strings.TrimSpace(apiErr.Code) == "unauthenticated"
}


func workerErrorFromControlErr(err error) *worker.APIError {
	apiErr, ok := err.(*gapcontrol.APIError)
	if !ok || apiErr == nil {
		return &worker.APIError{Code: worker.CodeInternal, Message: err.Error()}
	}
	return &worker.APIError{
		Code:    workerCodeFromControlCode(apiErr.Code),
		Message: strings.TrimSpace(apiErr.Message),
	}
}

func workerErrorFromControlDecision(decision gapcontrol.SpawnDecision) *worker.APIError {
	return &worker.APIError{
		Code:    workerCodeFromControlCode(decision.ReasonCode),
		Message: strings.TrimSpace(decision.Reason),
	}
}

func workerCodeFromControlCode(code string) string {
	switch strings.TrimSpace(code) {
	case "invalid_request", "unsupported_version":
		return worker.CodeInvalidRequest
	case "policy_denied", "unauthorized", "unauthenticated":
		return worker.CodePolicyDenied
	case "worker_not_found":
		return worker.CodeWorkerNotFound
	default:
		return worker.CodeInternal
	}
}
