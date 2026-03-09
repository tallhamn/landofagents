package agent

import "fmt"

// AddVolume appends a volume mount to an existing agent if it is not already present.
func (m *Manager) AddVolume(name, volume string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}

	a, exists := ef.Agents[name]
	if !exists {
		return fmt.Errorf("agent %q not found", name)
	}
	for _, v := range a.Volumes {
		if v == volume {
			return nil
		}
	}
	a.Volumes = append(a.Volumes, volume)
	ef.Agents[name] = a
	return m.save(ef)
}

// AddRememberedVolume appends a remembered run-time volume mount for an agent
// if it is not already present.
func (m *Manager) AddRememberedVolume(name, volume string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}
	a, exists := ef.Agents[name]
	if !exists {
		return fmt.Errorf("agent %q not found", name)
	}
	for _, v := range a.RememberedVolumes {
		if v == volume {
			return nil
		}
	}
	a.RememberedVolumes = append(a.RememberedVolumes, volume)
	ef.Agents[name] = a
	return m.save(ef)
}

// RemoveRememberedVolume removes a remembered volume mount from an agent.
func (m *Manager) RemoveRememberedVolume(name, volume string) error {
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
	for _, v := range a.RememberedVolumes {
		if v == volume {
			removed = true
			continue
		}
		kept = append(kept, v)
	}
	if !removed {
		return fmt.Errorf("remembered mount %q not found for agent %q", volume, name)
	}
	a.RememberedVolumes = kept
	ef.Agents[name] = a
	return m.save(ef)
}

// AddRememberedVolumeAll appends a remembered mount to all existing agents.
func (m *Manager) AddRememberedVolumeAll(volume string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}
	for name, a := range ef.Agents {
		found := false
		for _, v := range a.RememberedVolumes {
			if v == volume {
				found = true
				break
			}
		}
		if found {
			continue
		}
		a.RememberedVolumes = append(a.RememberedVolumes, volume)
		ef.Agents[name] = a
	}
	return m.save(ef)
}

// AddNeverMountDir stores an exact directory path that should not prompt for mount again.
func (m *Manager) AddNeverMountDir(name, dir string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}
	a, exists := ef.Agents[name]
	if !exists {
		return fmt.Errorf("agent %q not found", name)
	}
	for _, d := range a.NeverMountDirs {
		if d == dir {
			return nil
		}
	}
	a.NeverMountDirs = append(a.NeverMountDirs, dir)
	ef.Agents[name] = a
	return m.save(ef)
}

// AddNeverMountDirAll stores a never-mount directory for all existing agents.
func (m *Manager) AddNeverMountDirAll(dir string) error {
	ef, err := m.load()
	if err != nil {
		return err
	}
	for name, a := range ef.Agents {
		found := false
		for _, d := range a.NeverMountDirs {
			if d == dir {
				found = true
				break
			}
		}
		if found {
			continue
		}
		a.NeverMountDirs = append(a.NeverMountDirs, dir)
		ef.Agents[name] = a
	}
	return m.save(ef)
}
