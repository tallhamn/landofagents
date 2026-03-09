package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

type activitySummary struct {
	events        int
	commandEvents int
	httpEvents    int
	fileBatches   int
	fileUpdates   int
	hosts         map[string]int
	files         map[string]int
	first         time.Time
	last          time.Time
}

func collectActivitySummary(records []audit.Record, agentName string, sinceCutoff time.Time) activitySummary {
	s := activitySummary{
		hosts: map[string]int{},
		files: map[string]int{},
	}

	for _, r := range records {
		if agentName != "" && r.Agent != agentName {
			continue
		}
		if !sinceCutoff.IsZero() && !r.Timestamp.IsZero() && r.Timestamp.Before(sinceCutoff) {
			continue
		}
		if s.first.IsZero() || (!r.Timestamp.IsZero() && r.Timestamp.Before(s.first)) {
			s.first = r.Timestamp
		}
		if s.last.IsZero() || (!r.Timestamp.IsZero() && r.Timestamp.After(s.last)) {
			s.last = r.Timestamp
		}
		s.events++

		switch {
		case r.Action == "exec:Run":
			s.commandEvents++
		case r.Action == "http:Request":
			s.httpEvents++
			host := strings.TrimSpace(r.Resource)
			if host != "" {
				s.hosts[host]++
			}
		case r.DecisionPath == "activity_file" || r.Action == "file:UpdateSet":
			s.fileBatches++
			if n := contextInt(r.Context, "total_files"); n > 0 {
				s.fileUpdates += n
			}
			for _, f := range contextStringSlice(r.Context, "files") {
				s.files[f]++
			}
		}
	}

	return s
}


func contextInt(ctx map[string]any, key string) int {
	if ctx == nil {
		return 0
	}
	raw, ok := ctx[key]
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func contextStringSlice(ctx map[string]any, key string) []string {
	if ctx == nil {
		return nil
	}
	raw, ok := ctx[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return append([]string{}, v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s := strings.TrimSpace(fmt.Sprintf("%v", item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}


func printTopCounts(title string, counts map[string]int, limit int) {
	fmt.Printf("  %s:\n", title)
	if len(counts) == 0 {
		fmt.Printf("    (none)\n")
		return
	}
	type item struct {
		name  string
		count int
	}
	var items []item
	for k, v := range counts {
		items = append(items, item{name: k, count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	for _, it := range items {
		fmt.Printf("    - %s (%d)\n", it.name, it.count)
	}
}
