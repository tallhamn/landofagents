package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/marcusmom/land-of-agents/engine/runtime"
)

// LoadKit loads a complete permission kit from a directory.
func LoadKit(dir string) (*Kit, error) {
	kit := &Kit{Dir: dir}

	// Load agent registry (agents.yml).
	entitiesPath := AgentRegistryPath(dir)
	if err := loadYAML(entitiesPath, &kit.Entities); err != nil {
		return nil, fmt.Errorf("load agent registry: %w", err)
	}
	// Backfill agent names from map keys
	for name, agent := range kit.Entities.Agents {
		agent.Name = name
		kit.Entities.Agents[name] = agent
	}

	// Load protector.yml
	protectorPath := filepath.Join(dir, "config", "protector.yml")
	if err := loadYAML(protectorPath, &kit.Protector); err != nil {
		return nil, fmt.Errorf("load protector: %w", err)
	}

	// Load always-allowed.cedar
	alwaysAllowedPath := filepath.Join(dir, "config", "always-allowed.cedar")
	data, err := os.ReadFile(alwaysAllowedPath)
	if err != nil {
		return nil, fmt.Errorf("load always-allowed.cedar: %w", err)
	}
	kit.AlwaysAllowedCedar = string(data)

	// Load active policy set only.
	activeDir := filepath.Join(dir, "policies", "active")
	if err := addPolicyFiles(&kit.Policies, activeDir); err != nil {
		return nil, err
	}
	// Not an error if this directory doesn't exist yet — new kits start empty.

	return kit, nil
}

// GetAgent returns the agent config for a given name, or an error if not found.
func (k *Kit) GetAgent(name string) (Agent, error) {
	agent, ok := k.Entities.Agents[name]
	if !ok {
		return Agent{}, fmt.Errorf("agent %q not found in agent registry", name)
	}
	return agent, nil
}

// LoadAgentRuntime loads the runtime for the given agent.
// If the agent specifies runtime:, it loads from runtimes/<name>/ in the kit.
// If runtime is missing, it returns an error.
func (k *Kit) LoadAgentRuntime(agentName string) (*runtime.Runtime, error) {
	agent, err := k.GetAgent(agentName)
	if err != nil {
		return nil, err
	}

	if agent.Runtime != "" {
		rtDir := filepath.Join(k.Dir, "runtimes", agent.Runtime)
		return runtime.Load(rtDir)
	}

	return nil, fmt.Errorf("agent %q has no runtime set", agentName)
}
