package loaadvisor

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func filesystemRootFromRecord(r audit.Record) string {
	root := strings.TrimSpace(r.Resource)
	if root == "" {
		if raw, ok := r.Context["root"]; ok {
			root = strings.TrimSpace(fmt.Sprintf("%v", raw))
		}
	}
	return root
}

func cleanJoin(root, rel string) string {
	return path.Clean(path.Join(root, rel))
}

func dirOf(resource string) string {
	return path.Clean(path.Dir(resource))
}

func containerSuggestionDir(root, full string) string {
	root = path.Clean(root)
	full = path.Clean(full)
	if root == "" || full == "" {
		return "/workspace"
	}
	rel := strings.TrimPrefix(full, root)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return root
	}
	first := rel
	if idx := strings.Index(first, "/"); idx > 0 {
		first = first[:idx]
	}
	if path.Ext(first) != "" {
		return root
	}
	if first == "." || first == "" {
		return root
	}
	return path.Clean(path.Join(root, first))
}

func addFilesystemSuggestion(target map[string]*filesystemSuggestionAccum, dir, mode, example string, ts time.Time) {
	dir = path.Clean(strings.TrimSpace(dir))
	if dir == "" || dir == "." {
		return
	}
	cur := target[dir]
	if cur == nil {
		cur = &filesystemSuggestionAccum{
			TargetDir: dir,
			Mode:      mode,
			Examples:  map[string]bool{},
		}
		target[dir] = cur
	}
	cur.Count++
	if ts.After(cur.LastSeen) {
		cur.LastSeen = ts
	}
	if cur.Mode != "rw" && mode == "rw" {
		cur.Mode = "rw"
	}
	if strings.TrimSpace(example) != "" {
		cur.Examples[example] = true
	}
}

func suggestedContainerMountTarget(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" || !strings.HasPrefix(resource, "/") {
		return ""
	}
	clean := path.Clean(resource)
	base := path.Base(clean)
	if strings.Contains(base, ".") {
		clean = path.Dir(clean)
	}
	if clean == "." {
		return ""
	}
	return clean
}
