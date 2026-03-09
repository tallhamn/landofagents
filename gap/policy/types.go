package policy

const VersionV1 = "gap.policy.v1"

type PolicyBundle struct {
	Version        string       `json:"version"`
	BundleID       string       `json:"bundle_id"`
	ScopeID        string       `json:"scope_id"`
	PolicyHash     string       `json:"policy_hash"`
	PolicyKinds    []string     `json:"policy_kinds"`
	Capabilities   Capabilities `json:"capabilities"`
	CompiledFormat string       `json:"compiled_format,omitempty"` // e.g. cedar; for application-level evaluation
	CompiledRules  []string     `json:"compiled_rules,omitempty"` // opaque to GAP core
	CreatedAt      string       `json:"created_at"`               // RFC3339
}

type Capabilities struct {
	Network NetworkCapability `json:"network"`
	Mounts  []MountEntry      `json:"mounts"`
	Secrets SecretsCapability `json:"secrets"`
}

type NetworkCapability struct {
	AllowHosts   []string `json:"allow_hosts,omitempty"`
	AllowDomains []string `json:"allow_domains,omitempty"`
	DenyHosts    []string `json:"deny_hosts,omitempty"`
	DenyDomains  []string `json:"deny_domains,omitempty"`
}

type MountEntry struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Access string `json:"access"` // read_only|read_write
	Kind   string `json:"kind"`   // bind|named_volume|ephemeral
}

type SecretsCapability struct {
	AllowRefs []string `json:"allow_refs,omitempty"`
	Exposure  string   `json:"exposure,omitempty"` // least|standard
}

type ActivationRecord struct {
	Version      string `json:"version"`
	ActivationID string `json:"activation_id"`
	ScopeID      string `json:"scope_id"`
	PolicyHash   string `json:"policy_hash"`
	ActivatedAt  string `json:"activated_at"` // RFC3339
	ActivatedBy  string `json:"activated_by"` // human|authority|automation
	Source       string `json:"source,omitempty"`
	ReviewRef    string `json:"review_ref,omitempty"`
}

type DecisionReason struct {
	ReasonCode          string   `json:"reason_code"`
	Reason              string   `json:"reason"`
	MatchedRuleIDs      []string `json:"matched_rule_ids,omitempty"`
	MissingCapabilities []string `json:"missing_capabilities,omitempty"`
}
