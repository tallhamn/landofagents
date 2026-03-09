package approval

import (
	"os"
	"path/filepath"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

// skipExisting sets file offsets to current file sizes so we don't
// re-surface denials from previous sessions.
func (w *Watcher) skipExisting() {
	entries, err := os.ReadDir(w.auditDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}
		path := filepath.Join(w.auditDir, entry.Name())
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		w.fileOffsets[path] = info.Size()
	}
}

// pollNewDenials reads any new denial records from the audit directory.
func (w *Watcher) pollNewDenials() []audit.Record {
	entries, err := os.ReadDir(w.auditDir)
	if err != nil {
		return nil
	}

	var denials []audit.Record
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".jsonl" {
			continue
		}
		path := filepath.Join(w.auditDir, entry.Name())
		for _, r := range w.readNewRecords(path) {
			if (w.agent == "" || r.Agent == w.agent) && !w.seen[r.ID] {
				if r.Decision == "deny" || (w.includePermits && r.Decision == "permit") {
					w.seen[r.ID] = true
					denials = append(denials, r)
				}
			}
		}
	}
	return denials
}
