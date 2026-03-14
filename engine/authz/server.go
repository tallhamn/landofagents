// Package authz implements the Envoy ext_authz decision service for network egress.
//
// Request path:
//   - Envoy forwards outbound HTTP/S metadata to this service
//   - authz loads current Cedar policy set from kit storage
//   - authz evaluates host/domain access for the requesting agent
//   - authz returns allow/deny and records an audit event
//
// Mode behavior:
//   - enforce: deny when policy does not permit
//   - log: allow but log denied decision for review
//   - ask: hold denied request while waiting for approval activation
//
// This package is intentionally network-focused; filesystem/secret activity is
// handled elsewhere.
package authz

import (
	"net/http"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

// Mode controls how the ext_authz server handles Cedar denials.
type Mode string

const (
	ModeEnforce Mode = "enforce" // deny → 403 (default)
	ModeLog     Mode = "log"     // deny → log + 200 (permit all, log what would be denied)
	ModeAsk     Mode = "ask"     // deny → hold connection, poll for approval
)

// Server is the ext_authz HTTP server.
type Server struct {
	kitDir         string
	agent          string
	runID          string
	logger         auditWriter
	mode           Mode
	ApproveTimeout time.Duration // how long to hold connection in gate mode (default 120s)
}

type auditWriter interface {
	Log(audit.Record) error
}

// NewServer creates a new ext_authz server.
func NewServer(kitDir, agent, runID string, logger auditWriter, mode Mode) *Server {
	if mode == "" {
		mode = ModeEnforce
	}
	mode = normalizeMode(mode)
	return &Server{
		kitDir:         kitDir,
		agent:          agent,
		runID:          strings.TrimSpace(runID),
		logger:         logger,
		mode:           mode,
		ApproveTimeout: 120 * time.Second,
	}
}

func (s *Server) logAudit(r audit.Record) {
	if s.logger != nil {
		s.logger.Log(r)
	}
}

func normalizeMode(mode Mode) Mode {
	switch strings.ToLower(string(mode)) {
	case "", string(ModeEnforce):
		return ModeEnforce
	case string(ModeLog), "observe":
		return ModeLog
	case string(ModeAsk), "gate":
		return ModeAsk
	default:
		return ModeEnforce
	}
}

// Handler returns the HTTP handler for ext_authz requests.
// Each request re-reads policies from disk so that policy activations take effect immediately.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Envoy ext_authz with path_prefix="/check" sends POST /check{path} with the
	// original Host header. The "/" catch-all handles both /check* and direct calls.
	mux.HandleFunc("/", s.handleCheck)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
