package loaauthority

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

func (s *Service) authenticatePrincipal(uid int) (principalContext, *control.APIError) {
	byUID, err := loadPrincipals(s.kitDir)
	if err != nil {
		return principalContext{ID: fmt.Sprintf("uid:%d", uid)}, &control.APIError{
			Code:    "unauthenticated",
			Message: err.Error(),
		}
	}
	b, ok := byUID[uid]
	if !ok {
		return principalContext{ID: fmt.Sprintf("uid:%d", uid)}, &control.APIError{
			Code:    "unauthenticated",
			Message: fmt.Sprintf("no principal mapping for uid %d in config/%s", uid, principalsConfigFilename),
		}
	}
	return principalContext{ID: b.ID, AllowAgents: b.AllowAgents}, nil
}

func mapWorkerError(err error) (*control.APIError, bool) {
	apiErr, ok := err.(*worker.APIError)
	if !ok || apiErr == nil {
		return nil, false
	}
	switch strings.TrimSpace(apiErr.Code) {
	case worker.CodeInvalidRequest, worker.CodeUnsupported:
		return &control.APIError{Code: "invalid_request", Message: strings.TrimSpace(apiErr.Message)}, true
	case worker.CodePolicyDenied:
		return &control.APIError{Code: "policy_denied", Message: strings.TrimSpace(apiErr.Message)}, true
	case worker.CodeWorkerNotFound:
		return &control.APIError{Code: "worker_not_found", Message: strings.TrimSpace(apiErr.Message)}, true
	default:
		return &control.APIError{Code: "internal_error", Message: strings.TrimSpace(apiErr.Message)}, true
	}
}

func normalizeRequestID(requestID string) string {
	requestID = strings.TrimSpace(requestID)
	if requestID != "" {
		return requestID
	}
	buf := make([]byte, 6)
	if _, err := crand.Read(buf); err != nil {
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	return "req_" + hex.EncodeToString(buf)
}

func newDecisionID() string {
	buf := make([]byte, 8)
	if _, err := crand.Read(buf); err != nil {
		return fmt.Sprintf("dec_%d", time.Now().UnixNano())
	}
	return "dec_" + hex.EncodeToString(buf)
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *Service) policyHashForAgent(agentID string) string {
	activeDir := filepath.Join(s.kitDir, "policies", "active")
	entries, err := os.ReadDir(activeDir)
	if err != nil {
		return "sha256:unavailable"
	}
	prefix := strings.TrimSpace(agentID) + "-"
	h := sha256.New()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cedar") {
			continue
		}
		name := e.Name()
		if agentID != "" && !strings.HasPrefix(name, prefix) && !strings.HasPrefix(name, "all-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(activeDir, name))
		if err != nil {
			continue
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
