package loaadvisor

import (
	"sort"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/audit"
)

func collectFilesystemSuggestions(records []audit.Record, agentName string, since time.Time, a agent.Agent) []FilesystemSuggestion {
	coverage := buildMountCoverage(a)
	suggestions := map[string]*filesystemSuggestionAccum{}

	for _, r := range records {
		if r.Agent != agentName {
			continue
		}
		if !r.Timestamp.IsZero() && !since.IsZero() && r.Timestamp.Before(since) {
			continue
		}
		collectFilesystemSuggestionFromRecord(suggestions, r)
	}

	out := make([]FilesystemSuggestion, 0, len(suggestions))
	for _, s := range suggestions {
		if mountCovers(coverage, s.TargetDir, s.Mode) {
			continue
		}
		out = append(out, FilesystemSuggestion{
			TargetDir: s.TargetDir,
			Count:     s.Count,
			LastSeen:  s.LastSeen,
			Examples:  sortedMapKeys(s.Examples),
			Mode:      s.Mode,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].TargetDir < out[j].TargetDir
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func collectFilesystemSuggestionFromRecord(target map[string]*filesystemSuggestionAccum, r audit.Record) {
	if strings.TrimSpace(r.DecisionPath) == "activity_file" || strings.TrimSpace(r.Action) == "file:UpdateSet" {
		root := filesystemRootFromRecord(r)
		if root == "" || !strings.HasPrefix(root, "/") {
			return
		}
		for _, rel := range contextStringSlice(r.Context, "files") {
			full := cleanJoin(root, rel)
			targetDir := containerSuggestionDir(root, full)
			addFilesystemSuggestion(target, targetDir, "rw", full, r.Timestamp)
		}
		return
	}

	if strings.HasPrefix(strings.TrimSpace(r.Action), "fs:") && strings.ToLower(strings.TrimSpace(r.Decision)) == "deny" {
		resource := strings.TrimSpace(r.Resource)
		if resource == "" || !strings.HasPrefix(resource, "/") {
			return
		}
		mode := "ro"
		if strings.Contains(strings.ToLower(r.Action), "write") {
			mode = "rw"
		}
		targetDir := suggestedContainerMountTarget(resource)
		if targetDir == "" {
			targetDir = dirOf(resource)
		}
		addFilesystemSuggestion(target, targetDir, mode, resource, r.Timestamp)
	}
}
