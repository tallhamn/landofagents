package loaauthority

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const principalsConfigFilename = "principals.yml"

type principalsConfig struct {
	Principals []principalBinding `yaml:"principals"`
}

type principalBinding struct {
	ID          string   `yaml:"id"`
	UID         int      `yaml:"uid"`
	AllowAgents []string `yaml:"allow_agents"`
}

type principalContext struct {
	ID          string
	AllowAgents []string
}

func loadPrincipals(kitDir string) (map[int]principalBinding, error) {
	path := filepath.Join(kitDir, "config", principalsConfigFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	var cfg principalsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	byUID := make(map[int]principalBinding, len(cfg.Principals))
	for i, p := range cfg.Principals {
		p.ID = strings.TrimSpace(p.ID)
		if p.ID == "" {
			return nil, fmt.Errorf("%s: principals[%d].id is required", path, i)
		}
		if p.UID < 0 {
			return nil, fmt.Errorf("%s: principals[%d].uid must be >= 0", path, i)
		}
		if _, exists := byUID[p.UID]; exists {
			return nil, fmt.Errorf("%s: duplicate uid %d", path, p.UID)
		}
		p.AllowAgents = normalizeAgents(p.AllowAgents)
		byUID[p.UID] = p
	}
	return byUID, nil
}

func normalizeAgents(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func allowsAgent(allowAgents []string, agentID string) bool {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return false
	}
	for _, allow := range allowAgents {
		switch strings.TrimSpace(allow) {
		case "*":
			return true
		case agentID:
			return true
		}
	}
	return false
}
