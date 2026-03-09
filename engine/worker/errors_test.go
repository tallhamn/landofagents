package worker

import "testing"

func TestExitCodeMapping(t *testing.T) {
	tests := []struct {
		code string
		want int
	}{
		{code: CodeInvalidRequest, want: 2},
		{code: CodeUnsupported, want: 2},
		{code: CodePolicyDenied, want: 3},
		{code: CodeWorkerNotFound, want: 4},
		{code: CodeWorkerStartTO, want: 5},
		{code: CodeWorkerTerminateTO, want: 5},
		{code: CodeInternal, want: 6},
		{code: "unknown", want: 6},
	}
	for _, tt := range tests {
		if got := ExitCode(&APIError{Code: tt.code, Message: "x"}); got != tt.want {
			t.Fatalf("ExitCode(%q)=%d want %d", tt.code, got, tt.want)
		}
	}
}
