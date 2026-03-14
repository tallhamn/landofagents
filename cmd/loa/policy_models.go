package main

import "regexp"

type activePolicyInfo struct {
	Name   string
	Scope  string // "agent" or "all"
	Effect string // "allow", "deny", or "unknown"
}

type effectivePolicyEntry struct {
	Effect   string // allow|deny|unknown
	Action   string
	Resource string
	Scope    string // all|agent
	Source   string
}

type cedarRule struct {
	Effect   string // allow|deny|unknown
	Action   string
	Resource string
}

var (
	cedarStmtPattern      = regexp.MustCompile(`(?s)(permit|forbid)\s*\((.*?)\);`)
	cedarActionPattern    = regexp.MustCompile(`Action::"([^"]+)"`)
	cedarResourcePattern  = regexp.MustCompile(`Resource::"([^"]+)"`)
	cedarPrincipalPattern = regexp.MustCompile(`Agent::"([^"]+)"`)
)
