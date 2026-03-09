package worker

import "fmt"

const (
	CodeInvalidRequest    = "invalid_request"
	CodeUnsupported       = "unsupported_version"
	CodePolicyDenied      = "policy_denied"
	CodeWorkerNotFound    = "worker_not_found"
	CodeWorkerStartTO     = "worker_start_timeout"
	CodeWorkerTerminateTO = "worker_terminate_timeout"
	CodeWorkerCrashed     = "worker_crashed"
	CodeInternal          = "internal_error"
)

// APIError represents a structured worker API error.
type APIError struct {
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ExitCode maps API errors to CLI exit codes.
func ExitCode(err error) int {
	apiErr, ok := err.(*APIError)
	if !ok || apiErr == nil {
		return 6
	}
	switch apiErr.Code {
	case CodeInvalidRequest, CodeUnsupported:
		return 2
	case CodePolicyDenied:
		return 3
	case CodeWorkerNotFound:
		return 4
	case CodeWorkerStartTO, CodeWorkerTerminateTO:
		return 5
	default:
		return 6
	}
}
