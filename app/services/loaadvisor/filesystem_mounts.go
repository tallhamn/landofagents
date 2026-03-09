package loaadvisor

import (
	"path"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/agent"
)

func buildMountCoverage(a agent.Agent) []mountCoverage {
	cov := []mountCoverage{{Target: "/workspace", Mode: "rw"}}
	appendFromSpecs := func(specs []string) {
		for _, m := range specs {
			_, target, mode := parseMountSpec(m)
			if strings.TrimSpace(target) == "" {
				continue
			}
			cov = append(cov, mountCoverage{
				Target: path.Clean(strings.TrimSpace(target)),
				Mode:   mode,
			})
		}
	}
	appendFromSpecs(a.Volumes)
	appendFromSpecs(a.RememberedVolumes)
	return cov
}

func mountCovers(coverage []mountCoverage, targetDir, neededMode string) bool {
	targetDir = path.Clean(strings.TrimSpace(targetDir))
	neededMode = strings.ToLower(strings.TrimSpace(neededMode))
	if neededMode == "" {
		neededMode = "rw"
	}
	for _, c := range coverage {
		base := path.Clean(strings.TrimSpace(c.Target))
		if base == "" {
			continue
		}
		if targetDir != base && !strings.HasPrefix(targetDir, strings.TrimSuffix(base, "/")+"/") {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(c.Mode))
		if mode == "" {
			mode = "rw"
		}
		if neededMode == "rw" && mode != "rw" {
			continue
		}
		return true
	}
	return false
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
