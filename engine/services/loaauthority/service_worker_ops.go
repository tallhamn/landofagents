package loaauthority

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/gap/control"
)

func (s *Service) StatusAsUID(ctx context.Context, uid int, req control.WorkerStatusRequest) (control.WorkerStatusResponse, error) {
	req.RequestID = normalizeRequestID(req.RequestID)
	principal, authErr := s.authenticatePrincipal(uid)
	if authErr != nil {
		return control.WorkerStatusResponse{}, authErr
	}
	if strings.TrimSpace(req.WorkerID) == "" {
		return control.WorkerStatusResponse{}, &control.APIError{Code: "invalid_request", Message: "worker_id is required"}
	}
	got, err := s.workers.Get(ctx, req.WorkerID)
	if err != nil {
		if apiErr, ok := mapWorkerError(err); ok {
			return control.WorkerStatusResponse{}, apiErr
		}
		return control.WorkerStatusResponse{}, err
	}
	if !allowsAgent(principal.AllowAgents, got.Agent) {
		return control.WorkerStatusResponse{}, &control.APIError{
			Code:    "unauthorized",
			Message: fmt.Sprintf("principal %q cannot access agent %q", principal.ID, got.Agent),
		}
	}
	return control.WorkerStatusResponse{
		Version:   control.VersionV1,
		RequestID: strings.TrimSpace(req.RequestID),
		WorkerID:  got.WorkerID,
		AgentID:   got.Agent,
		SessionID: got.SessionID,
		Status:    got.Status,
	}, nil
}

func (s *Service) TerminateAsUID(ctx context.Context, uid int, req control.TerminateRequest) (control.SpawnDecision, error) {
	req.RequestID = normalizeRequestID(req.RequestID)
	principal, authErr := s.authenticatePrincipal(uid)
	decision := control.SpawnDecision{
		Version:              control.VersionV1,
		RequestID:            strings.TrimSpace(req.RequestID),
		DecisionID:           newDecisionID(),
		Decision:             "deny",
		EffectivePrincipalID: principal.ID,
		PolicyHash:           s.policyHashForAgent(""),
		ExpiresAt:            control.DefaultExpiry(time.Now()),
	}
	if authErr != nil {
		decision.ReasonCode = authErr.Code
		decision.Reason = authErr.Message
		return decision, nil
	}
	if strings.TrimSpace(req.WorkerID) == "" {
		decision.ReasonCode = "invalid_request"
		decision.Reason = "worker_id is required"
		return decision, nil
	}

	got, err := s.workers.Get(ctx, req.WorkerID)
	if err != nil {
		if apiErr, ok := mapWorkerError(err); ok {
			decision.ReasonCode = apiErr.Code
			decision.Reason = apiErr.Message
			return decision, nil
		}
		return decision, err
	}
	decision.EffectiveAgentID = got.Agent
	decision.PolicyHash = s.policyHashForAgent(got.Agent)
	if !allowsAgent(principal.AllowAgents, got.Agent) {
		decision.ReasonCode = "unauthorized"
		decision.Reason = fmt.Sprintf("principal %q cannot manage agent %q", principal.ID, got.Agent)
		return decision, nil
	}

	terminated, err := s.workers.Terminate(ctx, req.WorkerID, req.Reason)
	if err != nil {
		if apiErr, ok := mapWorkerError(err); ok {
			decision.ReasonCode = apiErr.Code
			decision.Reason = apiErr.Message
			return decision, nil
		}
		return decision, err
	}
	decision.Decision = "permit"
	decision.WorkerID = terminated.WorkerID
	decision.Status = terminated.Status
	decision.ReasonCode = ""
	decision.Reason = ""
	return decision, nil
}

func (s *Service) ListAsUID(ctx context.Context, uid int, requestID string) (control.WorkerListResponse, error) {
	requestID = normalizeRequestID(requestID)
	principal, authErr := s.authenticatePrincipal(uid)
	if authErr != nil {
		return control.WorkerListResponse{}, authErr
	}
	listed, err := s.workers.List(ctx)
	if err != nil {
		if apiErr, ok := mapWorkerError(err); ok {
			return control.WorkerListResponse{}, apiErr
		}
		return control.WorkerListResponse{}, err
	}
	out := control.WorkerListResponse{Version: control.VersionV1}
	for _, w := range listed.Workers {
		if !allowsAgent(principal.AllowAgents, w.Agent) {
			continue
		}
		out.Workers = append(out.Workers, control.WorkerStatusResponse{
			Version:   control.VersionV1,
			RequestID: strings.TrimSpace(requestID),
			WorkerID:  w.WorkerID,
			AgentID:   w.Agent,
			SessionID: w.SessionID,
			Status:    w.Status,
		})
	}
	return out, nil
}
