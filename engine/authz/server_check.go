package authz

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/oneshot"
	"github.com/marcusmom/land-of-agents/engine/protector"
)

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	meta := extractCheckMeta(r)
	if meta.Domain == "" {
		s.denyMissingDomain(w, meta.Method, start)
		return
	}
	if s.handleOneTimeDecision(w, meta, start) {
		return
	}

	kit, eval, err := s.loadEvaluatorForCheck()
	if err != nil {
		log.Printf("authz: %v", err)
		writeDeny(w, s.agent, meta.Domain, fmt.Sprintf("internal error: %v", err))
		return
	}
	defer eval.Cleanup()

	decision, matchedResource, err := evaluateRequest(eval, s.agent, meta.Domain)
	latency := time.Since(start).Milliseconds()
	scope := scopeForAgent(kit, s.agent)

	if err != nil {
		log.Printf("authz: evaluation error for %s: %v", meta.Domain, err)
		s.logAudit(audit.Record{
			Agent:        s.agent,
			Scope:        scope,
			Action:       "http:Request",
			Resource:     meta.Domain,
			Decision:     "deny",
			DecisionPath: "error",
			DenialReason: fmt.Sprintf("evaluation error: %v", err),
			Context:      s.auditContext(),
			LatencyMs:    latency,
		})
		writeDeny(w, s.agent, meta.Domain, fmt.Sprintf("evaluation error: %v", err))
		return
	}

	if decision == protector.CedarPermit {
		if matchedResource != meta.Domain {
			log.Printf("authz: ALLOW %s %s %s (%dms) via %s", s.agent, meta.Method, meta.Domain, latency, matchedResource)
		} else {
			log.Printf("authz: ALLOW %s %s %s (%dms)", s.agent, meta.Method, meta.Domain, latency)
		}
		s.logAudit(audit.Record{
			Agent:        s.agent,
			Scope:        scope,
			Action:       "http:Request",
			Resource:     meta.Domain,
			Decision:     "permit",
			DecisionPath: "policy",
			Context:      s.auditContext(),
			LatencyMs:    latency,
		})
		w.Header().Set("x-loa-decision", "allow")
		w.Header().Set("x-loa-agent", s.agent)
		w.WriteHeader(http.StatusOK)
		return
	}

	reason := fmt.Sprintf("No policy permits %s to reach %s", s.agent, meta.Domain)
	switch s.mode {
	case ModeLog:
		log.Printf("authz: LOG-DENY %s %s %s (%dms) — would be denied", s.agent, meta.Method, meta.Domain, latency)
		s.logAudit(audit.Record{
			Agent:        s.agent,
			Scope:        scope,
			Action:       "http:Request",
			Resource:     meta.Domain,
			Decision:     "deny",
			DecisionPath: "log",
			DenialReason: reason,
			Context:      s.auditContext(),
			LatencyMs:    latency,
		})
		w.Header().Set("x-loa-decision", "log")
		w.Header().Set("x-loa-agent", s.agent)
		w.WriteHeader(http.StatusOK)
	case ModeAsk:
		s.handleApproveWait(w, r, meta.Domain, reason, scope, start)
	default:
		log.Printf("authz: DENY %s %s %s (%dms) — %s %s", s.agent, meta.Method, meta.Domain, latency, meta.Method, meta.Path)
		s.logAudit(audit.Record{
			Agent:        s.agent,
			Scope:        scope,
			Action:       "http:Request",
			Resource:     meta.Domain,
			Decision:     "deny",
			DecisionPath: "policy",
			DenialReason: reason,
			Context:      s.auditContext(),
			LatencyMs:    latency,
		})
		writeDeny(w, s.agent, meta.Domain, reason)
	}
}

func (s *Server) denyMissingDomain(w http.ResponseWriter, method string, start time.Time) {
	latency := time.Since(start).Milliseconds()
	reason := "missing destination host metadata"
	log.Printf("authz: DENY %s %s (%dms) — %s", s.agent, method, latency, reason)
	s.logAudit(audit.Record{
		Agent:        s.agent,
		Scope:        s.agent,
		Action:       "http:Request",
		Resource:     "",
		Decision:     "deny",
		DecisionPath: "error",
		DenialReason: reason,
		Context:      s.auditContext(),
		LatencyMs:    latency,
	})
	writeDeny(w, s.agent, "", reason)
}

func (s *Server) handleOneTimeDecision(w http.ResponseWriter, meta checkMeta, start time.Time) bool {
	one, ok := s.consumeOneTimeDecision(meta.Domain)
	if !ok {
		return false
	}
	latency := time.Since(start).Milliseconds()
	scope := s.agent
	switch one.Effect {
	case oneshot.EffectAllow:
		log.Printf("authz: ALLOW-ONCE %s %s %s (%dms)", s.agent, meta.Method, meta.Domain, latency)
		s.logAudit(audit.Record{
			Agent:        s.agent,
			Scope:        scope,
			Action:       "http:Request",
			Resource:     meta.Domain,
			Decision:     "permit",
			DecisionPath: "one_time_allow",
			Context:      s.auditContext(),
			LatencyMs:    latency,
		})
		w.Header().Set("x-loa-decision", "allow")
		w.Header().Set("x-loa-agent", s.agent)
		w.WriteHeader(http.StatusOK)
		return true
	case oneshot.EffectDeny:
		reason := fmt.Sprintf("Blocked once by operator: %s %s", meta.Method, meta.Path)
		log.Printf("authz: DENY-ONCE %s %s %s (%dms)", s.agent, meta.Method, meta.Domain, latency)
		s.logAudit(audit.Record{
			Agent:        s.agent,
			Scope:        scope,
			Action:       "http:Request",
			Resource:     meta.Domain,
			Decision:     "deny",
			DecisionPath: "one_time_deny",
			DenialReason: reason,
			Context:      s.auditContext(),
			LatencyMs:    latency,
		})
		writeDeny(w, s.agent, meta.Domain, reason)
		return true
	}
	return false
}
