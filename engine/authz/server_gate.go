package authz

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/config"
	"github.com/marcusmom/land-of-agents/engine/oneshot"
	"github.com/marcusmom/land-of-agents/engine/protector"
)

// handleApproveWait holds the HTTP connection in gate mode, polling for
// new active Cedar files until the request is permitted or the timeout expires.
// The host-side `loa watch` activates policies via the approval pipeline.
func (s *Server) handleApproveWait(w http.ResponseWriter, r *http.Request, domain, reason, scope string, startTime time.Time) {
	latency := time.Since(startTime).Milliseconds()
	log.Printf("authz: DENY %s %s (%dms) — waiting for approval (timeout %s)", s.agent, domain, latency, s.ApproveTimeout)
	s.logger.Log(audit.Record{
		Agent:        s.agent,
		Scope:        scope,
		Action:       "http:Request",
		Resource:     domain,
		Decision:     "deny",
		DecisionPath: "policy",
		DenialReason: reason,
		Context:      s.auditContext(),
		LatencyMs:    latency,
	})

	deadline := time.After(s.ApproveTimeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			log.Printf("authz: TIMEOUT %s %s — approval not received within %s", s.agent, domain, s.ApproveTimeout)
			writeDeny(w, s.agent, domain, fmt.Sprintf("approval timeout: %s", reason))
			return
		case <-ticker.C:
			switch s.recheckPermission(domain) {
			case recheckAllow:
				totalLatency := time.Since(startTime).Milliseconds()
				log.Printf("authz: APPROVED %s %s (%dms) — permission granted during wait", s.agent, domain, totalLatency)
				s.logger.Log(audit.Record{
					Agent:        s.agent,
					Scope:        scope,
					Action:       "http:Request",
					Resource:     domain,
					Decision:     "permit",
					DecisionPath: "approve_wait",
					Context:      s.auditContext(),
					LatencyMs:    totalLatency,
				})
				w.Header().Set("x-loa-decision", "allow")
				w.Header().Set("x-loa-agent", s.agent)
				w.WriteHeader(http.StatusOK)
				return
			case recheckDeny:
				totalLatency := time.Since(startTime).Milliseconds()
				blockReason := "Blocked once by operator during gate wait"
				log.Printf("authz: DENY-ONCE %s %s (%dms) — blocked during wait", s.agent, domain, totalLatency)
				s.logger.Log(audit.Record{
					Agent:        s.agent,
					Scope:        scope,
					Action:       "http:Request",
					Resource:     domain,
					Decision:     "deny",
					DecisionPath: "one_time_deny",
					DenialReason: blockReason,
					Context:      s.auditContext(),
					LatencyMs:    totalLatency,
				})
				writeDeny(w, s.agent, domain, blockReason)
				return
			}
		case <-r.Context().Done():
			log.Printf("authz: client disconnected while waiting for approval of %s %s", s.agent, domain)
			return
		}
	}
}

type recheckResult int

const (
	recheckPending recheckResult = iota
	recheckAllow
	recheckDeny
)

// recheckPermission re-reads one-time decisions and Cedar policy during gate wait.
func (s *Server) recheckPermission(domain string) recheckResult {
	if one, ok := s.consumeOneTimeDecision(domain); ok {
		if one.Effect == oneshot.EffectAllow {
			return recheckAllow
		}
		if one.Effect == oneshot.EffectDeny {
			return recheckDeny
		}
	}

	kit, err := config.LoadKit(s.kitDir)
	if err != nil {
		return recheckPending
	}
	entitiesJSON, err := kit.Entities.EntitiesToCedarJSON()
	if err != nil {
		return recheckPending
	}
	eval, err := protector.NewCedarEvaluatorFromSources(
		[]byte(kit.AlwaysAllowedCedar), kit.Policies, entitiesJSON)
	if err != nil {
		return recheckPending
	}
	defer eval.Cleanup()
	decision, _, err := evaluateRequest(eval, s.agent, domain)
	if err == nil && decision == protector.CedarPermit {
		return recheckAllow
	}
	return recheckPending
}

func (s *Server) consumeOneTimeDecision(domain string) (oneshot.Decision, bool) {
	one, ok, err := oneshot.ConsumeMatch(s.kitDir, s.agent, "http:Request", domain, s.runID)
	if err != nil {
		log.Printf("authz: oneshot consume error: %v", err)
		return oneshot.Decision{}, false
	}
	return one, ok
}

func (s *Server) auditContext() map[string]any {
	if strings.TrimSpace(s.runID) == "" {
		return nil
	}
	return map[string]any{
		"run_id": s.runID,
	}
}
