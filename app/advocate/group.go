// Package advocate drafts English permission proposals from denials using an LLM.
package advocate

import (
	"net"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

// DenialGroup batches related denials for a single Advocate call.
type DenialGroup struct {
	Agent   string
	Service string // registrable domain: "google.com", "gmail.com"
	Denials []audit.Record
}

// GroupDenials groups denial records by agent, then by service domain.
// Each group becomes one Advocate LLM call.
func GroupDenials(denials []audit.Record) []DenialGroup {
	// agent -> service -> denials
	type groupKey struct {
		agent, service string
	}
	order := []groupKey{}
	groups := map[groupKey][]audit.Record{}

	for _, d := range denials {
		svc := extractService(d.Resource)
		k := groupKey{d.Agent, svc}
		if _, exists := groups[k]; !exists {
			order = append(order, k)
		}
		groups[k] = append(groups[k], d)
	}

	result := make([]DenialGroup, 0, len(order))
	for _, k := range order {
		result = append(result, DenialGroup{
			Agent:   k.agent,
			Service: k.service,
			Denials: groups[k],
		})
	}
	return result
}

// extractService extracts the registrable domain from a resource string.
// "calendar.google.com" → "google.com"
// "api.wrike.com" → "wrike.com"
// "localhost" → "localhost"
// Non-domain resources (file paths, etc.) return the resource as-is.
func extractService(resource string) string {
	// File paths and empty strings pass through
	if resource == "" || strings.HasPrefix(resource, "/") {
		return resource
	}

	// Strip port if present
	host := resource
	if h, _, err := net.SplitHostPort(resource); err == nil {
		host = h
	}

	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// Return last two parts: "calendar.google.com" → "google.com"
	return strings.Join(parts[len(parts)-2:], ".")
}
