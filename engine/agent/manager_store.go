package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func (m *Manager) registryPath() string {
	return filepath.Join(m.kitDir, "config", agentRegistryFilename)
}

func (m *Manager) load() (*entitiesFile, error) {
	path := m.registryPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty structure
			return &entitiesFile{
				Agents:      make(map[string]Agent),
				AgentGroups: map[string]groupMembers{"agent": {Members: []string{}}},
			}, nil
		}
		return nil, fmt.Errorf("read agent registry: %w", err)
	}

	var ef entitiesFile
	if err := yaml.Unmarshal(data, &ef); err != nil {
		return nil, fmt.Errorf("parse agent registry: %w", err)
	}

	if ef.Agents == nil {
		ef.Agents = make(map[string]Agent)
	}
	if ef.AgentGroups == nil {
		ef.AgentGroups = map[string]groupMembers{"agent": {Members: []string{}}}
	}

	return &ef, nil
}

func (m *Manager) save(ef *entitiesFile) error {
	data, err := yaml.Marshal(ef)
	if err != nil {
		return fmt.Errorf("marshal agent registry: %w", err)
	}

	path := m.registryPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}
