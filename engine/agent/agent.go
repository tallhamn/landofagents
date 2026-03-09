// Package agent manages named agent definitions in the agent registry.
package agent

import (
	"fmt"
	"os"
	"path/filepath"
)

// Agent represents a named agent.
type Agent struct {
	Name              string   `yaml:"-"`
	Runtime           string   `yaml:"runtime,omitempty"`
	Mode              string   `yaml:"mode,omitempty"` // enforce, log, or ask (default ask)
	Scope             string   `yaml:"scope"`
	Volumes           []string `yaml:"volumes,omitempty"`
	AllowedEnv        []string `yaml:"allowed_env,omitempty"`
	AllowedSecrets    []string `yaml:"allowed_secrets,omitempty"`
	RememberedVolumes []string `yaml:"remembered_volumes,omitempty"`
	NeverMountDirs    []string `yaml:"never_mount_dirs,omitempty"`
}

// EffectiveMode returns the agent's mode, defaulting to "ask".
func (a Agent) EffectiveMode() string {
	if a.Mode == "" {
		return "ask"
	}
	return a.Mode
}

const (
	agentRegistryFilename = "agents.yml"
)

// entitiesFile represents the full agent registry structure.
type entitiesFile struct {
	Agents          map[string]Agent        `yaml:"agents"`
	AgentGroups     map[string]groupMembers `yaml:"agent_groups"`
	RecipientGroups map[string]groupMembers `yaml:"recipient_groups,omitempty"`
}

type groupMembers struct {
	Members []string `yaml:"members"`
}

// Manager provides CRUD operations on named agents.
type Manager struct {
	kitDir string
}

// NewManager creates a manager for the given kit directory.
func NewManager(kitDir string) *Manager {
	return &Manager{kitDir: kitDir}
}

// CreateOpts configures agent creation.
type CreateOpts struct {
	Runtime        string // runtime name
	Mode           string // enforce, log, or ask (default ask)
	Volumes        []string
	AllowedEnv     []string // optional per-agent env allowlist (runtime-declared vars only)
	AllowedSecrets []string // optional per-agent secret grants (by secret ref name)
}

// Create adds a new named agent to the registry.
func (m *Manager) Create(name string, opts CreateOpts) error {
	ef, err := m.load()
	if err != nil {
		return err
	}

	if _, exists := ef.Agents[name]; exists {
		return fmt.Errorf("agent %q already exists (delete with: loa agent delete %s)", name, name)
	}
	if opts.Runtime == "" {
		return fmt.Errorf("agent %q requires runtime", name)
	}

	agent := Agent{
		Runtime:        opts.Runtime,
		Mode:           opts.Mode,
		Scope:          name,
		Volumes:        opts.Volumes,
		AllowedEnv:     opts.AllowedEnv,
		AllowedSecrets: opts.AllowedSecrets,
	}
	ef.Agents[name] = agent

	// Ensure agent is in the "agent" group
	group := ef.AgentGroups["agent"]
	found := false
	for _, member := range group.Members {
		if member == name {
			found = true
			break
		}
	}
	if !found {
		group.Members = append(group.Members, name)
		ef.AgentGroups["agent"] = group
	}

	return m.save(ef)
}

// List returns all named agents.
func (m *Manager) List() ([]Agent, error) {
	ef, err := m.load()
	if err != nil {
		return nil, err
	}

	var agents []Agent
	for name, a := range ef.Agents {
		a.Name = name
		agents = append(agents, a)
	}
	return agents, nil
}

// Get returns a single agent by name.
func (m *Manager) Get(name string) (Agent, error) {
	ef, err := m.load()
	if err != nil {
		return Agent{}, err
	}

	a, ok := ef.Agents[name]
	if !ok {
		return Agent{}, fmt.Errorf("agent %q not found", name)
	}
	a.Name = name
	return a, nil
}

// Delete removes a named agent from the registry and cleans up its workspace.
func (m *Manager) Delete(name string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}

	if _, exists := ef.Agents[name]; !exists {
		return fmt.Errorf("agent %q not found", name)
	}

	delete(ef.Agents, name)

	// Remove from agent group
	group := ef.AgentGroups["agent"]
	var members []string
	for _, member := range group.Members {
		if member != name {
			members = append(members, member)
		}
	}
	group.Members = members
	ef.AgentGroups["agent"] = group

	if err := m.save(ef); err != nil {
		return err
	}

	// Clean up workspace directory
	wsDir := filepath.Join(m.kitDir, "workspaces", name)
	if err := os.RemoveAll(wsDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove workspace: %w", err)
	}

	// Clean up runtime Cedar policy
	policyFile := filepath.Join(m.kitDir, "policies", "active", fmt.Sprintf("_runtime-%s.cedar", name))
	if err := os.Remove(policyFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove runtime policy: %w", err)
	}

	return nil
}
