package control

import "time"

const VersionV1 = "gap.control.v1"

type SpawnRequest struct {
	Version        string            `json:"version"`
	RequestID      string            `json:"request_id"`
	AgentID        string            `json:"agent_id"`
	SessionID      string            `json:"session_id"`
	WorkloadID     string            `json:"workload_id"`
	ParentWorkerID string            `json:"parent_worker_id,omitempty"`
	Runtime        string            `json:"runtime,omitempty"`
	IssuedAt       string            `json:"issued_at"`
	Nonce          string            `json:"nonce,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`

	// Env holds caller-provided environment variable overrides (key=value).
	// These are intersected with the agent's allowed_env policy before injection.
	Env map[string]string `json:"env,omitempty"`

	MountProfile struct {
		Volumes []string `json:"volumes,omitempty"`
	} `json:"mount_profile,omitempty"`

	NetworkProfile struct {
		Mode               string `json:"mode,omitempty"`
		InitialPolicyScope string `json:"initial_policy_scope,omitempty"`
	} `json:"network_profile,omitempty"`

	SecretsProfile struct {
		Refs     []string `json:"refs,omitempty"`
		Exposure string   `json:"exposure,omitempty"`
	} `json:"secrets_profile,omitempty"`
}

type SpawnDecision struct {
	Version              string `json:"version"`
	RequestID            string `json:"request_id"`
	DecisionID           string `json:"decision_id"`
	Decision             string `json:"decision"` // permit|deny
	EffectivePrincipalID string `json:"effective_principal_id"`
	EffectiveAgentID     string `json:"effective_agent_id"`
	PolicyHash           string `json:"policy_hash"`
	AuthorityID          string `json:"authority_id,omitempty"`
	DecidedAt            string `json:"decided_at,omitempty"`
	ExpiresAt            string `json:"expires_at"`

	WorkerID string `json:"worker_id,omitempty"`
	Status   string `json:"status,omitempty"`

	ReasonCode string `json:"reason_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type TerminateRequest struct {
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
	WorkerID  string `json:"worker_id"`
	Reason    string `json:"reason,omitempty"`
}

type WorkerStatusRequest struct {
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
	WorkerID  string `json:"worker_id"`
}

type WorkerStatusResponse struct {
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
	WorkerID  string `json:"worker_id"`
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

type WorkerListResponse struct {
	Version string                 `json:"version"`
	Workers []WorkerStatusResponse `json:"workers"`
}

func DefaultExpiry(now time.Time) string {
	return now.Add(30 * time.Minute).UTC().Format(time.RFC3339)
}
