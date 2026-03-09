package main

import (
	"path/filepath"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func loadAuditRecords(kitDir string) ([]audit.Record, error) {
	logger, err := audit.NewLogger(filepath.Join(kitDir, "audit"))
	if err != nil {
		return nil, err
	}
	return logger.ReadAll()
}
