package contain

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func printEffectiveMounts(opts Options, volumes []string) {
	workspaceHost := filepath.Join(opts.KitDir, "workspaces", opts.AgentName)
	fmt.Printf("  Mounts:\n")
	fmt.Printf("    %-45s %-28s %s\n", "Host", "Container", "Mode")
	fmt.Printf("    %-45s %-28s %s\n", workspaceHost, "/workspace", "rw")
	for _, v := range volumes {
		host, container, mode := parseMountSpec(v)
		if host == "" || container == "" {
			continue
		}
		fmt.Printf("    %-45s %-28s %s\n", host, container, mode)
	}
}

func parseMountSpec(spec string) (host, container, mode string) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 {
		return spec, "", "rw"
	}

	mode = "rw"
	if len(parts) >= 3 {
		last := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
		if last == "ro" || last == "rw" {
			mode = last
			container = parts[len(parts)-2]
			host = strings.Join(parts[:len(parts)-2], ":")
			if host == "" {
				host = spec
			}
			return host, container, mode
		}
	}

	host = parts[0]
	container = strings.Join(parts[1:], ":")
	if host == "" {
		host = spec
	}
	return host, container, mode
}

// forbiddenHostPaths are host paths that must never be mounted into agent containers.
var forbiddenHostPaths = []string{
	"/",
	"/boot",
	"/dev",
	"/etc",
	"/proc",
	"/sys",
	"/var/run/docker.sock",
	"/run/docker.sock",
}

// validateHostPath checks that a host mount source is not a forbidden system path.
// Returns an error if the path is forbidden.
func validateHostPath(hostPath string) error {
	cleaned := filepath.Clean(hostPath)
	for _, forbidden := range forbiddenHostPaths {
		if cleaned == forbidden || strings.HasPrefix(cleaned, forbidden+string(filepath.Separator)) {
			return fmt.Errorf("mount source %q is a protected system path", cleaned)
		}
	}
	return nil
}

func resolveUserVolumes(agentVolumes, extraVolumes, managedTargets []string, useOnlyExtra bool) ([]string, error) {
	var source []string
	if useOnlyExtra {
		source = append(source, extraVolumes...)
	} else {
		source = append(source, agentVolumes...)
		source = append(source, extraVolumes...)
	}
	var volumes []string
	for _, v := range source {
		expanded := expandTildeVolume(v)
		if volumeConflictsWithTargets(expanded, managedTargets) {
			continue
		}
		host, _, _ := parseMountSpec(expanded)
		if err := validateHostPath(host); err != nil {
			return nil, err
		}
		volumes = append(volumes, expanded)
	}
	return volumes, nil
}

// expandTildeVolume expands ~ in the host portion of a volume mount string.
// e.g. "~/.claude.json:/home/node/.claude.json:ro" → "/Users/x/.claude.json:/home/node/.claude.json:ro"
func expandTildeVolume(vol string) string {
	if len(vol) == 0 || vol[0] != '~' {
		return vol
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return vol
	}
	// Only expand ~ at the start of the host path (before first :)
	parts := strings.SplitN(vol, ":", 2)
	if strings.HasPrefix(parts[0], "~/") {
		parts[0] = filepath.Join(home, parts[0][2:])
	} else if parts[0] == "~" {
		parts[0] = home
	}
	return strings.Join(parts, ":")
}

func volumeConflictsWithTargets(vol string, targets []string) bool {
	mountTarget := containerMountPath(vol)
	if mountTarget == "" {
		return false
	}
	for _, target := range targets {
		if mountTarget == target {
			return true
		}
	}
	return false
}

func containerMountPath(vol string) string {
	parts := strings.Split(vol, ":")
	if len(parts) < 2 {
		return ""
	}
	last := parts[len(parts)-1]
	switch last {
	case "ro", "rw", "z", "Z", "cached", "delegated", "consistent", "nocopy":
		if len(parts) >= 3 {
			return parts[len(parts)-2]
		}
		return ""
	default:
		return last
	}
}
