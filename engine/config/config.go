// Package config loads and parses LOA configuration files.
package config

import "path/filepath"

// Kit represents a loaded permission kit (the top-level config directory).
type Kit struct {
	Dir                string
	Entities           Entities
	Protector          Protector
	AlwaysAllowedCedar string   // Raw cedar policy text
	Policies           []string // Paths to active compiled .cedar files.
}

const (
	agentRegistryFilename = "agents.yml"
)

// AgentRegistryPath returns the agent registry file path.
func AgentRegistryPath(dir string) string {
	return filepath.Join(dir, "config", agentRegistryFilename)
}

// Agent represents a named agent definition from the agent registry.
type Agent struct {
	Name           string   `yaml:"-"`
	Runtime        string   `yaml:"runtime,omitempty"`
	Scope          string   `yaml:"scope"`
	Volumes        []string `yaml:"volumes,omitempty"`
	AllowedEnv     []string `yaml:"allowed_env,omitempty"`
	AllowedSecrets []string `yaml:"allowed_secrets,omitempty"`
}

// Entities represents the parsed agent registry.
type Entities struct {
	Agents          map[string]Agent        `yaml:"agents"`
	AgentGroups     map[string]GroupMembers `yaml:"agent_groups"`
	RecipientGroups map[string]GroupMembers `yaml:"recipient_groups"`
}

// GroupMembers holds the members list for a group.
type GroupMembers struct {
	Members []string `yaml:"members"`
}

// ToolMapping represents a single tool mapping from protector.yml.
type ToolMapping struct {
	Executable        string            `yaml:"executable,omitempty"`
	Pattern           string            `yaml:"pattern,omitempty"`
	SubcommandPattern string            `yaml:"subcommand_pattern,omitempty"`
	Action            string            `yaml:"action"`
	ResourceExtractor string            `yaml:"resource_extractor,omitempty"`
	ContextExtractors map[string]string `yaml:"context_extractors,omitempty"`
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	LogDir           string `yaml:"log_dir"`
	Format           string `yaml:"format"`
	LogPermitted     bool   `yaml:"log_permitted"`
	LogDenied        bool   `yaml:"log_denied"`
	LogAlwaysAllowed bool   `yaml:"log_always_allowed"`
}

// Protector represents the parsed protector.yml.
type Protector struct {
	ToolMappings    []ToolMapping `yaml:"tool_mappings"`
	DefaultUnmapped string        `yaml:"default_unmapped"` // "deny" or "permit"
	DisclaimerText  string        `yaml:"disclaimer_text,omitempty"`
	Audit           AuditConfig   `yaml:"audit"`
}
