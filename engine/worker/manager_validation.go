package worker

import (
	"fmt"
	"strings"
)

func validateLaunch(req LaunchRequest) error {
	if strings.TrimSpace(req.Version) == "" {
		return &APIError{Code: CodeInvalidRequest, Message: "version is required"}
	}
	if strings.TrimSpace(req.Version) != VersionV1 {
		return &APIError{Code: CodeUnsupported, Message: fmt.Sprintf("unsupported version %q", req.Version)}
	}
	if strings.TrimSpace(req.Agent) == "" {
		return &APIError{Code: CodeInvalidRequest, Message: "agent is required"}
	}
	if strings.TrimSpace(req.SessionID) == "" {
		return &APIError{Code: CodeInvalidRequest, Message: "session_id is required"}
	}
	if strings.TrimSpace(req.WorkloadID) == "" {
		return &APIError{Code: CodeInvalidRequest, Message: "workload_id is required"}
	}
	return nil
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "log", "observe":
		return "log"
	case "ask", "gate":
		return "ask"
	default:
		return "enforce"
	}
}
