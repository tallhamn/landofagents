package control

import "fmt"

// APIError is a structured GAP control-plane error.
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
