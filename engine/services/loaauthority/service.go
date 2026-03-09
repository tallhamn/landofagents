package loaauthority

import (
	"context"
	"os"

	"github.com/marcusmom/land-of-agents/gap/control"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

type workerManager interface {
	Launch(ctx context.Context, req worker.LaunchRequest) (worker.LaunchResponse, error)
	Get(ctx context.Context, workerID string) (worker.WorkerResponse, error)
	Terminate(ctx context.Context, workerID string, reason string) (worker.TerminateResponse, error)
	List(ctx context.Context) (worker.ListResponse, error)
}

type Service struct {
	kitDir  string
	workers workerManager
}

func New(kitDir string, workerOpts ...worker.ManagerOption) (*Service, error) {
	mgr, err := worker.NewManager(kitDir, workerOpts...)
	if err != nil {
		return nil, err
	}
	return &Service{kitDir: kitDir, workers: mgr}, nil
}

func newWithWorkers(kitDir string, mgr workerManager) *Service {
	return &Service{kitDir: kitDir, workers: mgr}
}

func (s *Service) Spawn(ctx context.Context, req control.SpawnRequest) (control.SpawnDecision, error) {
	return s.SpawnAsUID(ctx, os.Getuid(), req)
}

func (s *Service) Status(ctx context.Context, req control.WorkerStatusRequest) (control.WorkerStatusResponse, error) {
	return s.StatusAsUID(ctx, os.Getuid(), req)
}

func (s *Service) Terminate(ctx context.Context, req control.TerminateRequest) (control.SpawnDecision, error) {
	return s.TerminateAsUID(ctx, os.Getuid(), req)
}

func (s *Service) List(ctx context.Context, requestID string) (control.WorkerListResponse, error) {
	return s.ListAsUID(ctx, os.Getuid(), requestID)
}
