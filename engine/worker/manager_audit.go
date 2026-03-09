package worker

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/secrets"
)

func (m *Manager) logLaunchDeniedIfPolicy(req LaunchRequest, err error) {
	apiErr, ok := err.(*APIError)
	if !ok || apiErr == nil || apiErr.Code != CodePolicyDenied {
		return
	}
	_ = m.logLaunchDenied(req, apiErr)
}

func (m *Manager) logLaunchDenied(req LaunchRequest, deniedErr *APIError) string {
	r := audit.Record{
		ID:           newAuditID(),
		Timestamp:    time.Now().UTC(),
		Agent:        req.Agent,
		Scope:        req.Agent,
		Action:       "worker:LaunchDenied",
		Resource:     strings.TrimSpace(req.WorkloadID),
		Decision:     "deny",
		DecisionPath: "worker_control_plane",
		DenialReason: strings.TrimSpace(deniedErr.Message),
		Context: map[string]any{
			"version":          VersionV1,
			"principal_id":     strings.TrimSpace(req.PrincipalID),
			"session_id":       strings.TrimSpace(req.SessionID),
			"workload_id":      strings.TrimSpace(req.WorkloadID),
			"parent_worker_id": strings.TrimSpace(req.ParentWorkerID),
			"runtime":          runtimeName(req, ""),
			"mode":             normalizeMode(req.NetworkProfile.Mode),
			"initial_scope":    strings.TrimSpace(req.NetworkProfile.InitialPolicyScope),
			"secret_exposure":  strings.TrimSpace(req.SecretsProfile.Exposure),
			"labels":           cloneLabels(req.Labels),
			"mounts":           normalizeVolumeList(req.MountProfile.Volumes),
			"secret_refs":      secrets.NormalizeRefs(req.SecretsProfile.Refs),
		},
	}
	_ = m.ledger.AppendRecord(r)
	return r.ID
}

func (m *Manager) logLaunch(rec Record) string {
	r := audit.Record{
		ID:           newAuditID(),
		Timestamp:    time.Now().UTC(),
		Agent:        rec.Agent,
		Scope:        rec.Agent,
		Action:       "worker:Launch",
		Resource:     rec.WorkerID,
		Decision:     "permit",
		DecisionPath: "worker_control_plane",
		Context: map[string]any{
			"version":          VersionV1,
			"principal_id":     strings.TrimSpace(rec.PrincipalID),
			"worker_id":        rec.WorkerID,
			"session_id":       rec.SessionID,
			"workload_id":      rec.WorkloadID,
			"parent_worker_id": rec.ParentWorkerID,
			"depth":            rec.Depth,
			"secret_refs":      rec.SecretRefs,
			"mode":             rec.Mode,
			"labels":           cloneLabels(rec.Labels),
			"runtime":          rec.Runtime,
			"run_id":           rec.RunID,
		},
	}
	_ = m.ledger.AppendRecord(r)
	return r.ID
}

func (m *Manager) logLaunchFailure(req LaunchRequest, launchErr error) string {
	r := audit.Record{
		ID:           newAuditID(),
		Timestamp:    time.Now().UTC(),
		Agent:        req.Agent,
		Scope:        req.Agent,
		Action:       "worker:LaunchFailed",
		Resource:     req.WorkloadID,
		Decision:     "deny",
		DecisionPath: "worker_control_plane",
		DenialReason: strings.TrimSpace(launchErr.Error()),
		Context: map[string]any{
			"version":          VersionV1,
			"principal_id":     strings.TrimSpace(req.PrincipalID),
			"session_id":       req.SessionID,
			"workload_id":      req.WorkloadID,
			"parent_worker_id": strings.TrimSpace(req.ParentWorkerID),
			"mode":             normalizeMode(req.NetworkProfile.Mode),
			"initial_scope":    strings.TrimSpace(req.NetworkProfile.InitialPolicyScope),
			"secret_exposure":  strings.TrimSpace(req.SecretsProfile.Exposure),
			"labels":           cloneLabels(req.Labels),
			"secret_refs":      secrets.NormalizeRefs(req.SecretsProfile.Refs),
			"runtime":          runtimeName(req, ""),
		},
	}
	_ = m.ledger.AppendRecord(r)
	return r.ID
}

func (m *Manager) logTerminate(rec Record, reason string) string {
	r := audit.Record{
		ID:           newAuditID(),
		Timestamp:    time.Now().UTC(),
		Agent:        rec.Agent,
		Scope:        rec.Agent,
		Action:       "worker:Terminate",
		Resource:     rec.WorkerID,
		Decision:     "permit",
		DecisionPath: "worker_control_plane",
		Context: map[string]any{
			"version":          VersionV1,
			"principal_id":     strings.TrimSpace(rec.PrincipalID),
			"worker_id":        rec.WorkerID,
			"session_id":       rec.SessionID,
			"workload_id":      rec.WorkloadID,
			"parent_worker_id": rec.ParentWorkerID,
			"depth":            rec.Depth,
			"secret_refs":      rec.SecretRefs,
			"mode":             rec.Mode,
			"labels":           cloneLabels(rec.Labels),
			"runtime":          rec.Runtime,
			"reason":           strings.TrimSpace(reason),
		},
	}
	_ = m.ledger.AppendRecord(r)
	return r.ID
}

func (m *Manager) logTerminateFailure(rec Record, reason string, termErr error) string {
	r := audit.Record{
		ID:           newAuditID(),
		Timestamp:    time.Now().UTC(),
		Agent:        rec.Agent,
		Scope:        rec.Agent,
		Action:       "worker:TerminateFailed",
		Resource:     rec.WorkerID,
		Decision:     "deny",
		DecisionPath: "worker_control_plane",
		DenialReason: strings.TrimSpace(termErr.Error()),
		Context: map[string]any{
			"version":          VersionV1,
			"principal_id":     strings.TrimSpace(rec.PrincipalID),
			"worker_id":        rec.WorkerID,
			"session_id":       rec.SessionID,
			"workload_id":      rec.WorkloadID,
			"parent_worker_id": rec.ParentWorkerID,
			"depth":            rec.Depth,
			"secret_refs":      rec.SecretRefs,
			"mode":             rec.Mode,
			"labels":           cloneLabels(rec.Labels),
			"runtime":          rec.Runtime,
			"reason":           strings.TrimSpace(reason),
		},
	}
	_ = m.ledger.AppendRecord(r)
	return r.ID
}

func newAuditID() string {
	buf := make([]byte, 4)
	if _, err := crand.Read(buf); err != nil {
		return fmt.Sprintf("AUD-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("AUD-%d-%s", time.Now().UnixNano(), hex.EncodeToString(buf))
}
