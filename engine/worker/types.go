package worker

import "time"

const (
	VersionV1 = "loa.worker.v1"
)

// LaunchRequest defines the worker launch contract for loa.worker.v1.
type LaunchRequest struct {
	Version    string `json:"version"`
	Agent      string `json:"agent"`
	SessionID  string `json:"session_id"`
	WorkloadID string `json:"workload_id"`
	// PrincipalID identifies the authenticated caller initiating the launch.
	PrincipalID string `json:"principal_id,omitempty"`
	// ParentWorkerID links a child launch to its parent worker.
	ParentWorkerID string            `json:"parent_worker_id,omitempty"`
	Runtime        string            `json:"runtime,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`

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

// Endpoint describes an optional worker endpoint.
type Endpoint struct {
	Type string `json:"type"`
	URL  string `json:"url,omitempty"`
}

// AuditRef links responses to audit records.
type AuditRef struct {
	LaunchEventID string `json:"launch_event_id,omitempty"`
}

// LaunchResponse is returned by LaunchWorker.
type LaunchResponse struct {
	Version        string    `json:"version"`
	WorkerID       string    `json:"worker_id"`
	Agent          string    `json:"agent"`
	SessionID      string    `json:"session_id"`
	ParentWorkerID string    `json:"parent_worker_id,omitempty"`
	Depth          int       `json:"depth"`
	Status         string    `json:"status"`
	Endpoint       *Endpoint `json:"endpoint,omitempty"`
	AuditRef       *AuditRef `json:"audit_ref,omitempty"`
	ExpiresAt      string    `json:"expires_at,omitempty"`
}

// WorkerResponse is returned by GetWorker.
type WorkerResponse struct {
	Version        string `json:"version"`
	WorkerID       string `json:"worker_id"`
	Agent          string `json:"agent"`
	SessionID      string `json:"session_id"`
	ParentWorkerID string `json:"parent_worker_id,omitempty"`
	Depth          int    `json:"depth"`
	Status         string `json:"status"`
}

// TerminateResponse is returned by TerminateWorker.
type TerminateResponse struct {
	Version  string `json:"version"`
	WorkerID string `json:"worker_id"`
	Status   string `json:"status"`
}

// ListResponse is returned by ListWorkers.
type ListResponse struct {
	Version string           `json:"version"`
	Workers []WorkerResponse `json:"workers"`
}

// ErrorEnvelope is printed for machine-readable failures.
type ErrorEnvelope struct {
	Version string    `json:"version"`
	Error   ErrorBody `json:"error"`
}

// ErrorBody describes a worker API error.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Record tracks persisted worker lifecycle state.
type Record struct {
	WorkerID       string            `json:"worker_id"`
	Agent          string            `json:"agent"`
	SessionID      string            `json:"session_id"`
	WorkloadID     string            `json:"workload_id"`
	PrincipalID    string            `json:"principal_id,omitempty"`
	ParentWorkerID string            `json:"parent_worker_id,omitempty"`
	Depth          int               `json:"depth"`
	Runtime        string            `json:"runtime"`
	Status         string            `json:"status"`
	ComposePath    string            `json:"compose_path"`
	RunID          string            `json:"run_id"`
	Mounts         []string          `json:"mounts,omitempty"`
	SecretRefs     []string          `json:"secret_refs,omitempty"`
	Mode           string            `json:"mode"`
	Labels         map[string]string `json:"labels,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}
