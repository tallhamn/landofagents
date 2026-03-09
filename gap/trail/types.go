package trail

const VersionV1 = "gap.trail.v1"

// Event is the normalized trail event envelope for governed activity.
type Event struct {
	Version       string         `json:"version"`
	EventID       string         `json:"event_id,omitempty"`
	Timestamp     string         `json:"timestamp,omitempty"` // RFC3339
	EventType     string         `json:"event_type,omitempty"`
	PrincipalID   string         `json:"principal_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	WorkerID      string         `json:"worker_id,omitempty"`
	DecisionID    string         `json:"decision_id,omitempty"`
	AgentID       string         `json:"agent_id"`
	Scope         string         `json:"scope,omitempty"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource,omitempty"`
	Decision      string         `json:"decision,omitempty"` // permit|deny
	Enforced      bool           `json:"enforced"`
	DecisionPath  string         `json:"decision_path,omitempty"`
	PolicyRef     string         `json:"policy_ref,omitempty"`
	PermissionRef string         `json:"permission_ref,omitempty"`
	ReasonCode    string         `json:"reason_code,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	PolicyHash    string         `json:"policy_hash,omitempty"`
	LatencyMs     int64          `json:"latency_ms,omitempty"`
	Context       map[string]any `json:"context,omitempty"`
}
