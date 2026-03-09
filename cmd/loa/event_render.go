package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

type auditEventParts struct {
	Timestamp  string
	Decision   string
	Target     string
	Path       string
	Reason     string
	ShowReason bool
}

func renderAuditEventParts(r audit.Record) auditEventParts {
	ts := r.Timestamp.Local().Format("15:04:05")
	if r.Timestamp.IsZero() {
		ts = time.Now().Local().Format("15:04:05")
	}
	decision := strings.ToLower(strings.TrimSpace(r.Decision))
	action := strings.TrimSpace(r.Action)
	resource := strings.TrimSpace(r.Resource)
	target := ""
	switch {
	case action != "" && resource != "":
		target = fmt.Sprintf("%s -> %s", action, blueURLs(resource))
	case action != "":
		target = action
	case resource != "":
		target = blueURLs(resource)
	default:
		if cmd := extractCommandContext(r); cmd != "" {
			target = fmt.Sprintf("shell: %s", cmd)
		} else {
			target = "(no action/resource)"
		}
	}
	path := watchDecisionLabel(r)
	noPolicy := isNoPolicyDenialReason(r.DenialReason)
	showReason := r.DenialReason != "" && !noPolicy

	return auditEventParts{
		Timestamp:  ts,
		Decision:   decision,
		Target:     target,
		Path:       path,
		Reason:     r.DenialReason,
		ShowReason: showReason,
	}
}
