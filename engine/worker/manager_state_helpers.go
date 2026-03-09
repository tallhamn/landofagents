package worker

import (
	"fmt"
	"sort"
	"strings"
)

func normalizeVolumeList(vols []string) []string {
	if len(vols) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range vols {
		v := strings.TrimSpace(raw)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func findExistingWorker(st stateFile, agent, sessionID, workloadID string) (Record, bool) {
	for _, rec := range st.Workers {
		if rec.Agent == agent && rec.SessionID == sessionID && rec.WorkloadID == workloadID {
			if rec.Status == "running" || rec.Status == "pending" {
				return rec, true
			}
		}
	}
	return Record{}, false
}

func ensureExistingWorkerProfile(existing Record, requestedMounts, requestedSecretRefs []string, mode string) error {
	if existing.Mode != mode {
		return &APIError{
			Code:    CodePolicyDenied,
			Message: fmt.Sprintf("existing worker for (%s,%s,%s) is running with mode=%q (requested %q); use a new workload_id for a different profile", existing.Agent, existing.SessionID, existing.WorkloadID, existing.Mode, mode),
		}
	}
	if !equalStringSlices(existing.Mounts, requestedMounts) {
		return &APIError{
			Code:    CodePolicyDenied,
			Message: "existing worker for this agent/session/workload has different mounts; use a new workload_id for a different profile",
		}
	}
	if !equalStringSlices(existing.SecretRefs, requestedSecretRefs) {
		return &APIError{
			Code:    CodePolicyDenied,
			Message: "existing worker for this agent/session/workload has different secret refs; use a new workload_id for a different profile",
		}
	}
	return nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func resolveParentDepth(req LaunchRequest, st stateFile) (string, int, error) {
	parentID := strings.TrimSpace(req.ParentWorkerID)
	if parentID == "" {
		return "", 0, nil
	}
	parent, ok := st.Workers[parentID]
	if !ok {
		return "", 0, &APIError{
			Code:    CodeInvalidRequest,
			Message: fmt.Sprintf("parent_worker_id %q not found", parentID),
		}
	}
	if parent.Agent != req.Agent {
		return "", 0, &APIError{
			Code:    CodePolicyDenied,
			Message: fmt.Sprintf("parent worker %q belongs to agent %q, not %q", parentID, parent.Agent, req.Agent),
		}
	}
	if parent.Status != "running" && parent.Status != "pending" {
		return "", 0, &APIError{
			Code:    CodePolicyDenied,
			Message: fmt.Sprintf("parent worker %q is not active (status=%s)", parentID, parent.Status),
		}
	}
	return parentID, parent.Depth + 1, nil
}

func runtimeName(req LaunchRequest, fallback string) string {
	if v := strings.TrimSpace(req.Runtime); v != "" {
		return v
	}
	if strings.TrimSpace(fallback) != "" {
		return fallback
	}
	return "unknown"
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
