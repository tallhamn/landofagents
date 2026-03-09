package loaauthority

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

func (s *Service) SpawnAsUID(ctx context.Context, uid int, req control.SpawnRequest) (control.SpawnDecision, error) {
	req.RequestID = normalizeRequestID(req.RequestID)
	principal, authErr := s.authenticatePrincipal(uid)
	decision := control.SpawnDecision{
		Version:              control.VersionV1,
		RequestID:            strings.TrimSpace(req.RequestID),
		DecisionID:           newDecisionID(),
		Decision:             "deny",
		EffectivePrincipalID: principal.ID,
		EffectiveAgentID:     strings.TrimSpace(req.AgentID),
		PolicyHash:           s.policyHashForAgent(req.AgentID),
		ExpiresAt:            control.DefaultExpiry(time.Now()),
	}

	if authErr != nil {
		decision.ReasonCode = authErr.Code
		decision.Reason = authErr.Message
		return decision, nil
	}

	if reqErr := validateSpawnRequest(req); reqErr != nil {
		decision.ReasonCode = reqErr.Code
		decision.Reason = reqErr.Message
		return decision, nil
	}

	if !allowsAgent(principal.AllowAgents, req.AgentID) {
		decision.ReasonCode = "unauthorized"
		decision.Reason = fmt.Sprintf("principal %q cannot manage agent %q", principal.ID, strings.TrimSpace(req.AgentID))
		return decision, nil
	}

	workerReq := worker.LaunchRequest{
		Version:        worker.VersionV1,
		Agent:          strings.TrimSpace(req.AgentID),
		SessionID:      strings.TrimSpace(req.SessionID),
		WorkloadID:     strings.TrimSpace(req.WorkloadID),
		PrincipalID:    principal.ID,
		ParentWorkerID: strings.TrimSpace(req.ParentWorkerID),
		Runtime:        strings.TrimSpace(req.Runtime),
		Labels:         cloneMap(req.Labels),
	}
	workerReq.MountProfile.Volumes = append([]string{}, req.MountProfile.Volumes...)
	workerReq.NetworkProfile.Mode = strings.TrimSpace(req.NetworkProfile.Mode)
	workerReq.NetworkProfile.InitialPolicyScope = strings.TrimSpace(req.NetworkProfile.InitialPolicyScope)
	workerReq.SecretsProfile.Refs = append([]string{}, req.SecretsProfile.Refs...)
	workerReq.SecretsProfile.Exposure = strings.TrimSpace(req.SecretsProfile.Exposure)

	launched, err := s.workers.Launch(ctx, workerReq)
	if err != nil {
		if apiErr, ok := mapWorkerError(err); ok {
			decision.ReasonCode = apiErr.Code
			decision.Reason = apiErr.Message
			return decision, nil
		}
		return decision, err
	}

	decision.Decision = "permit"
	decision.WorkerID = launched.WorkerID
	decision.Status = launched.Status
	decision.ReasonCode = ""
	decision.Reason = ""
	return decision, nil
}

func validateSpawnRequest(req control.SpawnRequest) *control.APIError {
	if strings.TrimSpace(req.Version) == "" {
		return &control.APIError{Code: "invalid_request", Message: "version is required"}
	}
	if strings.TrimSpace(req.Version) != control.VersionV1 {
		return &control.APIError{Code: "unsupported_version", Message: fmt.Sprintf("unsupported version %q", req.Version)}
	}
	if strings.TrimSpace(req.RequestID) == "" {
		return &control.APIError{Code: "invalid_request", Message: "request_id is required"}
	}
	if strings.TrimSpace(req.AgentID) == "" {
		return &control.APIError{Code: "invalid_request", Message: "agent_id is required"}
	}
	if strings.TrimSpace(req.SessionID) == "" {
		return &control.APIError{Code: "invalid_request", Message: "session_id is required"}
	}
	if strings.TrimSpace(req.WorkloadID) == "" {
		return &control.APIError{Code: "invalid_request", Message: "workload_id is required"}
	}
	if strings.TrimSpace(req.Runtime) == "" {
		return &control.APIError{Code: "invalid_request", Message: "runtime is required"}
	}
	return nil
}
