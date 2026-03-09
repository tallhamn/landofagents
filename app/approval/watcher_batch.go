package approval

import "github.com/marcusmom/land-of-agents/engine/audit"

// dedupBatch removes duplicate denials within a batch by agent+action+resource.
func dedupBatch(records []audit.Record) []audit.Record {
	type key struct{ agent, action, resource string }
	seen := map[key]bool{}
	var deduped []audit.Record
	for _, r := range records {
		k := key{r.Agent, r.Action, r.Resource}
		if seen[k] {
			continue
		}
		seen[k] = true
		deduped = append(deduped, r)
	}
	return deduped
}
