package agent

import "fmt"

// AddAllowedSecret grants a secret reference to an agent if it is not already present.
func (m *Manager) AddAllowedSecret(name, secretRef string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}
	a, exists := ef.Agents[name]
	if !exists {
		return fmt.Errorf("agent %q not found", name)
	}
	for _, s := range a.AllowedSecrets {
		if s == secretRef {
			return nil
		}
	}
	a.AllowedSecrets = append(a.AllowedSecrets, secretRef)
	ef.Agents[name] = a
	return m.save(ef)
}

// RemoveAllowedSecret revokes a secret reference from an agent.
func (m *Manager) RemoveAllowedSecret(name, secretRef string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}
	a, exists := ef.Agents[name]
	if !exists {
		return fmt.Errorf("agent %q not found", name)
	}
	var kept []string
	removed := false
	for _, s := range a.AllowedSecrets {
		if s == secretRef {
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	if !removed {
		return fmt.Errorf("secret %q not granted to agent %q", secretRef, name)
	}
	a.AllowedSecrets = kept
	ef.Agents[name] = a
	return m.save(ef)
}
