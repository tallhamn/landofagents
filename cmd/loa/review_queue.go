package main

import (
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/netscope"
)

type denialDedupKey struct {
	agent        string
	action       string
	resource     string
	decisionPath string
}

func pendingReviewDenials(records []audit.Record, agentFilter string) []audit.Record {
	var filtered []audit.Record
	for _, r := range records {
		if !isDeniedRecord(r) {
			continue
		}
		if strings.TrimSpace(agentFilter) != "" && strings.TrimSpace(r.Agent) != strings.TrimSpace(agentFilter) {
			continue
		}
		filtered = append(filtered, r)
	}
	return deduplicateDeniedRecords(filtered)
}

func loadPendingReviewDenials(kitDir, agentFilter string) ([]audit.Record, error) {
	records, err := loadAuditRecords(kitDir)
	if err != nil {
		return nil, err
	}
	return pendingReviewDenials(records, agentFilter), nil
}

func deduplicateDeniedRecords(records []audit.Record) []audit.Record {
	seen := map[denialDedupKey]bool{}
	var denials []audit.Record
	for _, r := range records {
		if !isDeniedRecord(r) {
			continue
		}
		key := denialDedupKey{
			agent:        strings.TrimSpace(r.Agent),
			action:       strings.TrimSpace(r.Action),
			resource:     strings.TrimSpace(r.Resource),
			decisionPath: strings.TrimSpace(r.DecisionPath),
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		denials = append(denials, r)
	}
	return denials
}

func isDeniedRecord(r audit.Record) bool {
	return strings.EqualFold(strings.TrimSpace(r.Decision), "deny")
}

func isUnmappedDecisionPath(path string) bool {
	switch strings.TrimSpace(path) {
	case "activity_unmapped", "activity_flagged":
		return true
	default:
		return false
	}
}

func isUnmappedDeniedRecord(r audit.Record) bool {
	return isUnmappedDecisionPath(r.DecisionPath)
}

type denyBurstFilter struct {
	window time.Duration
	seen   map[denialDedupKey]time.Time
}

func newDenyBurstFilter(window time.Duration) *denyBurstFilter {
	if window <= 0 {
		window = 2 * time.Second
	}
	return &denyBurstFilter{
		window: window,
		seen:   map[denialDedupKey]time.Time{},
	}
}

func (f *denyBurstFilter) Filter(records []audit.Record, now time.Time) []audit.Record {
	if f == nil || len(records) == 0 {
		return records
	}
	var kept []audit.Record
	for _, r := range records {
		key := denialDedupKey{
			agent:        strings.TrimSpace(r.Agent),
			action:       strings.TrimSpace(r.Action),
			resource:     strings.TrimSpace(r.Resource),
			decisionPath: strings.TrimSpace(r.DecisionPath),
		}
		if last, ok := f.seen[key]; ok && now.Sub(last) < f.window {
			continue
		}
		f.seen[key] = now
		kept = append(kept, r)
	}
	f.gc(now)
	return kept
}

func (f *denyBurstFilter) gc(now time.Time) {
	for k, ts := range f.seen {
		if now.Sub(ts) > f.window*2 {
			delete(f.seen, k)
		}
	}
}

// approvedTracker remembers recently-approved resources so that stale denials
// arriving after a policy is applied get a brief info line instead of a re-prompt.
type approvedTracker struct {
	window  time.Duration
	entries map[string]time.Time // "agent\x00resource" → approval time
}

func newApprovedTracker(window time.Duration) *approvedTracker {
	if window <= 0 {
		window = 10 * time.Second
	}
	return &approvedTracker{
		window:  window,
		entries: map[string]time.Time{},
	}
}

func (t *approvedTracker) approvalKey(agent, resource string) string {
	return agent + "\x00" + resource
}

// Mark records approved denials so future matching denials are recognized.
func (t *approvedTracker) Mark(records []audit.Record, now time.Time) {
	for _, r := range records {
		agent := strings.TrimSpace(r.Agent)
		resource := strings.TrimSpace(r.Resource)
		t.entries[t.approvalKey(agent, resource)] = now
		// Also mark the registrable domain so subdomain denials match
		domain := netscope.EffectiveDomain(resource)
		if domain != "" && domain != resource {
			t.entries[t.approvalKey(agent, domain)] = now
		}
	}
}

// Filter separates denials into those needing review and those already covered.
func (t *approvedTracker) Filter(records []audit.Record, now time.Time) (kept, covered []audit.Record) {
	for _, r := range records {
		if t.isCovered(r, now) {
			covered = append(covered, r)
		} else {
			kept = append(kept, r)
		}
	}
	// GC old entries
	for k, ts := range t.entries {
		if now.Sub(ts) > t.window*2 {
			delete(t.entries, k)
		}
	}
	return kept, covered
}

func (t *approvedTracker) isCovered(r audit.Record, now time.Time) bool {
	agent := strings.TrimSpace(r.Agent)
	resource := strings.TrimSpace(r.Resource)
	// Exact resource match
	if ts, ok := t.entries[t.approvalKey(agent, resource)]; ok && now.Sub(ts) < t.window {
		return true
	}
	// Domain-level match (e.g. cdn.chatgpt.com covered by chatgpt.com approval)
	domain := netscope.EffectiveDomain(resource)
	if domain != "" && domain != resource {
		if ts, ok := t.entries[t.approvalKey(agent, domain)]; ok && now.Sub(ts) < t.window {
			return true
		}
	}
	return false
}
