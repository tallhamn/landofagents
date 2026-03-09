package loaadvisor

import (
	"sort"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/netscope"
)

func collectNetworkSuggestions(records []audit.Record, agentName string, since time.Time, scope string, activeEntries []PolicyEntry) []NetworkSuggestion {
	suggestions := map[string]*networkSuggestionAccum{}
	for _, r := range records {
		if r.Agent != agentName {
			continue
		}
		if !r.Timestamp.IsZero() && !since.IsZero() && r.Timestamp.Before(since) {
			continue
		}
		if strings.TrimSpace(r.Action) != "http:Request" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(r.Decision)) != "deny" {
			continue
		}
		if !isNoPolicyDenialReason(r.DenialReason) {
			continue
		}
		host := netscope.NormalizeHost(r.Resource)
		if host == "" {
			continue
		}
		resource := host
		if scope == "domain" {
			resource = netscope.EffectiveDomain(host)
		}
		if resource == "" {
			continue
		}
		if networkResourceAlreadyAllowed(activeEntries, host, resource) {
			continue
		}
		cur := suggestions[resource]
		if cur == nil {
			cur = &networkSuggestionAccum{
				Resource: resource,
				Examples: map[string]bool{},
			}
			suggestions[resource] = cur
		}
		cur.Count++
		if r.Timestamp.After(cur.LastSeen) {
			cur.LastSeen = r.Timestamp
		}
		cur.Examples[host] = true
	}

	out := make([]NetworkSuggestion, 0, len(suggestions))
	for _, s := range suggestions {
		out = append(out, NetworkSuggestion{
			Resource: s.Resource,
			Count:    s.Count,
			LastSeen: s.LastSeen,
			Examples: sortedMapKeys(s.Examples),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Resource < out[j].Resource
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func networkResourceAlreadyAllowed(entries []PolicyEntry, host, resource string) bool {
	for _, e := range entries {
		if e.Action != "http:Request" || e.Effect != "allow" {
			continue
		}
		allowed := strings.TrimSpace(e.Resource)
		if allowed == "" || allowed == "*" {
			continue
		}
		if allowed == resource {
			return true
		}
		// Domain-level allows cover host-level requests via authz fallback.
		if host != "" && allowed == netscope.EffectiveDomain(host) {
			return true
		}
	}
	return false
}
