package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func cwdAlreadyMounted(volumes []string, cwd string) bool {
	cwd = filepath.Clean(cwd)
	for _, v := range volumes {
		src := hostSourceFromVolume(v)
		if src == "" {
			continue
		}
		src = filepath.Clean(expandHome(src))
		if src == cwd || strings.HasPrefix(cwd, src+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func hostSourceFromVolume(volume string) string {
	src, _, _ := parseMountSpec(volume)
	return src
}

func containerTargetFromVolume(volume string) string {
	_, dst, _ := parseMountSpec(volume)
	return dst
}

func nextCWDMountTarget(volumes []string, baseName string) string {
	slug := safePathComponent(baseName)
	if slug == "" {
		slug = "project"
	}
	base := "/workspace/" + slug
	used := map[string]bool{}
	for _, v := range volumes {
		t := containerTargetFromVolume(v)
		if t != "" {
			used[t] = true
		}
	}
	if !used[base] {
		return base
	}
	for i := 2; i < 1000; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !used[candidate] {
			return candidate
		}
	}
	return base + "-mount"
}

func safePathComponent(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		if r == ' ' || r == '.' {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return "project"
	}
	return out
}

func expandHome(path string) string {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func rememberedVolumeForCWD(volumes []string, cwd string) string {
	cwd = filepath.Clean(cwd)
	for _, v := range volumes {
		src := hostSourceFromVolume(v)
		if src == "" {
			continue
		}
		src = filepath.Clean(expandHome(src))
		if src == cwd {
			return v
		}
	}
	return ""
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
