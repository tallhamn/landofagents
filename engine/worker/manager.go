package worker

import (
	"fmt"

	"github.com/marcusmom/land-of-agents/engine/contain"
	"github.com/marcusmom/land-of-agents/engine/services/loaledger"
)

type setupEnvFn func(opts contain.Options) (*contain.Environment, error)

// LaunchValidator validates launch requests before execution.
// Implementations enforce runtime-specific launch policies (e.g. OpenClaw strict mode).
// A nil validator skips all runtime-specific checks.
type LaunchValidator interface {
	ValidateWorkerLaunch(runtimeName string, requestedMounts []string, mode, initialScope, exposure string, labels map[string]string) error
}

// Manager handles worker lifecycle operations.
type Manager struct {
	kitDir    string
	ledger    *loaledger.Service
	docker    dockerClient
	setup     setupEnvFn
	validator LaunchValidator
}

// ManagerOption configures optional Manager behavior.
type ManagerOption func(*Manager)

// WithLaunchValidator sets a runtime-specific launch validator.
func WithLaunchValidator(v LaunchValidator) ManagerOption {
	return func(m *Manager) { m.validator = v }
}

// NewManager returns a worker manager for the provided kit.
func NewManager(kitDir string, opts ...ManagerOption) (*Manager, error) {
	ledger, err := loaledger.New(kitDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		kitDir: kitDir,
		ledger: ledger,
		docker: realDockerClient{},
		setup:  contain.SetupEnvironment,
	}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

func wrapInternal(err error) *APIError {
	if err == nil {
		return nil
	}
	if apiErr, ok := err.(*APIError); ok {
		return apiErr
	}
	return &APIError{Code: CodeInternal, Message: err.Error()}
}

func workerResponse(rec Record) WorkerResponse {
	return WorkerResponse{
		Version:        VersionV1,
		WorkerID:       rec.WorkerID,
		Agent:          rec.Agent,
		SessionID:      rec.SessionID,
		ParentWorkerID: rec.ParentWorkerID,
		Depth:          rec.Depth,
		Status:         rec.Status,
	}
}

func composeEnvWithKit(kitDir string) []string {
	return []string{fmt.Sprintf("LOA_KIT=%s", kitDir)}
}
