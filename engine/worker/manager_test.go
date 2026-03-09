package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marcusmom/land-of-agents/app/adapters/openclaw"
	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/contain"
	"github.com/marcusmom/land-of-agents/engine/secrets"
)

type fakeDocker struct {
	upCalls      int
	downCalls    int
	lastServices []string
	running      map[string]bool
	upErr        error
	downErr      error
}

func (f *fakeDocker) ComposeUp(_ string, _ []string, services ...string) error {
	f.upCalls++
	f.lastServices = append([]string{}, services...)
	return f.upErr
}

func (f *fakeDocker) ComposeDown(_ string, _ []string) error {
	f.downCalls++
	return f.downErr
}

func (f *fakeDocker) ServiceRunning(_ string, _ []string, service string) (bool, error) {
	if f.running == nil {
		return false, nil
	}
	return f.running[service], nil
}

func mustCreateAgent(t *testing.T, kitDir, name string, volumes []string) {
	t.Helper()
	mgr := agent.NewManager(kitDir)
	if err := mgr.Create(name, agent.CreateOpts{
		Runtime: "openclaw",
		Volumes: volumes,
	}); err != nil {
		t.Fatalf("create agent: %v", err)
	}
}

func mustCreateAgentWithSecrets(t *testing.T, kitDir, name string, volumes, allowedSecrets []string) {
	t.Helper()
	mgr := agent.NewManager(kitDir)
	if err := mgr.Create(name, agent.CreateOpts{
		Runtime:        "openclaw",
		Volumes:        volumes,
		AllowedSecrets: allowedSecrets,
	}); err != nil {
		t.Fatalf("create agent: %v", err)
	}
}

func mustDefineSecretRef(t *testing.T, kitDir, ref, env string, roles ...string) {
	t.Helper()
	reg, err := secrets.LoadRegistry(kitDir)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	if err := reg.SetDefinition(ref, env, "", roles); err != nil {
		t.Fatalf("set definition: %v", err)
	}
	if err := reg.Save(kitDir); err != nil {
		t.Fatalf("save registry: %v", err)
	}
}

func newTestManager(t *testing.T, kitDir string, docker *fakeDocker) *Manager {
	t.Helper()
	mgr, err := NewManager(kitDir)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr.docker = docker
	mgr.setup = func(opts contain.Options) (*contain.Environment, error) {
		return &contain.Environment{
			TmpDir:      filepath.Join(kitDir, "tmp", "loa-contain-test"),
			ComposePath: filepath.Join(kitDir, "tmp", "docker-compose.yaml"),
			KitDir:      kitDir,
		}, nil
	}
	return mgr
}

func newTestManagerWithValidator(t *testing.T, kitDir string, docker *fakeDocker) *Manager {
	t.Helper()
	mgr := newTestManager(t, kitDir, docker)
	mgr.validator = openclaw.StrictValidator{}
	return mgr
}

func readAuditRecords(t *testing.T, kitDir string) []audit.Record {
	t.Helper()
	l, err := audit.NewLogger(filepath.Join(kitDir, "audit"))
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}
	records, err := l.ReadAll()
	if err != nil {
		t.Fatalf("read audit records: %v", err)
	}
	return records
}

func contextValueString(ctx map[string]any, key string) string {
	if len(ctx) == 0 {
		return ""
	}
	raw, ok := ctx[key]
	if !ok || raw == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", raw))
}

func TestLaunchGetTerminateLifecycle(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "tool-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}

	launch, err := mgr.Launch(context.Background(), req)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if launch.Status != "running" {
		t.Fatalf("launch status=%q want running", launch.Status)
	}
	if !strings.HasPrefix(launch.WorkerID, "wk_") {
		t.Fatalf("worker id %q missing wk_ prefix", launch.WorkerID)
	}
	if launch.AuditRef == nil || launch.AuditRef.LaunchEventID == "" {
		t.Fatalf("expected launch audit ref, got %+v", launch.AuditRef)
	}
	if fd.upCalls != 1 {
		t.Fatalf("compose up calls=%d want 1", fd.upCalls)
	}
	if got, want := strings.Join(fd.lastServices, ","), "loa-authz,envoy,clawfather"; got != want {
		t.Fatalf("services=%q want %q", got, want)
	}

	getResp, err := mgr.Get(context.Background(), launch.WorkerID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if getResp.Status != "running" {
		t.Fatalf("get status=%q want running", getResp.Status)
	}

	termResp, err := mgr.Terminate(context.Background(), launch.WorkerID, "test")
	if err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if termResp.Status != "terminated" {
		t.Fatalf("terminate status=%q want terminated", termResp.Status)
	}
	if fd.downCalls != 1 {
		t.Fatalf("compose down calls=%d want 1", fd.downCalls)
	}

	getTerminated, err := mgr.Get(context.Background(), launch.WorkerID)
	if err != nil {
		t.Fatalf("get terminated: %v", err)
	}
	if getTerminated.Status != "terminated" {
		t.Fatalf("get terminated status=%q want terminated", getTerminated.Status)
	}
}

func TestLaunchAndTerminateAuditIncludePrincipalID(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:     VersionV1,
		Agent:       "clawfather",
		SessionID:   "sess-1",
		WorkloadID:  "tool-1",
		PrincipalID: "gateway:clawfather",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}

	launch, err := mgr.Launch(context.Background(), req)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if _, err := mgr.Terminate(context.Background(), launch.WorkerID, "test"); err != nil {
		t.Fatalf("terminate: %v", err)
	}

	records := readAuditRecords(t, kit)
	var launchPrincipal string
	var terminatePrincipal string
	for _, r := range records {
		if r.Resource != launch.WorkerID {
			continue
		}
		switch r.Action {
		case "worker:Launch":
			launchPrincipal = contextValueString(r.Context, "principal_id")
		case "worker:Terminate":
			terminatePrincipal = contextValueString(r.Context, "principal_id")
		}
	}
	if launchPrincipal != "gateway:clawfather" {
		t.Fatalf("launch principal_id=%q want gateway:clawfather", launchPrincipal)
	}
	if terminatePrincipal != "gateway:clawfather" {
		t.Fatalf("terminate principal_id=%q want gateway:clawfather", terminatePrincipal)
	}
}

func TestLaunchIdempotentByAgentSessionWorkload(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawcus", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawcus": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawcus",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}

	first, err := mgr.Launch(context.Background(), req)
	if err != nil {
		t.Fatalf("first launch: %v", err)
	}
	second, err := mgr.Launch(context.Background(), req)
	if err != nil {
		t.Fatalf("second launch: %v", err)
	}
	if first.WorkerID != second.WorkerID {
		t.Fatalf("idempotent launch worker_id mismatch: first=%q second=%q", first.WorkerID, second.WorkerID)
	}
	if fd.upCalls != 1 {
		t.Fatalf("compose up calls=%d want 1", fd.upCalls)
	}
}

func TestLaunchIdempotentRejectsDifferentSecretRefs(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgentWithSecrets(
		t,
		kit,
		"clawcus",
		[]string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"},
		[]string{"telegram.bot_token", "model.openrouter"},
	)
	mustDefineSecretRef(t, kit, "telegram.bot_token", "TELEGRAM_BOT_TOKEN", secrets.RoleWorker)
	mustDefineSecretRef(t, kit, "model.openrouter", "OPENROUTER_API_KEY", secrets.RoleWorker)

	fd := &fakeDocker{running: map[string]bool{"clawcus": true}}
	mgr := newTestManager(t, kit, fd)

	first := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawcus",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	first.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	first.SecretsProfile.Refs = []string{"telegram.bot_token"}
	if _, err := mgr.Launch(context.Background(), first); err != nil {
		t.Fatalf("first launch: %v", err)
	}

	second := first
	second.SecretsProfile.Refs = []string{"model.openrouter"}
	_, err := mgr.Launch(context.Background(), second)
	if err == nil {
		t.Fatal("expected launch denial for changed idempotent secret profile")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodePolicyDenied {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodePolicyDenied)
	}
	if !strings.Contains(apiErr.Message, "different secret refs") {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
	if fd.upCalls != 1 {
		t.Fatalf("compose up calls=%d want 1", fd.upCalls)
	}
}

func TestLaunchConcurrentIdempotentByAgentSessionWorkload(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawcus", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawcus": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawcus",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}

	const n = 12
	ids := make(chan string, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := mgr.Launch(context.Background(), req)
			if err != nil {
				errs <- err
				return
			}
			ids <- resp.WorkerID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)

	for err := range errs {
		t.Fatalf("unexpected launch error: %v", err)
	}
	var first string
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
		if first == "" {
			first = id
		}
	}
	if len(seen) != 1 {
		t.Fatalf("expected one worker id across concurrent idempotent launches, got %v", seen)
	}
	if fd.upCalls != 1 {
		t.Fatalf("compose up calls=%d want 1", fd.upCalls)
	}
}

func TestLaunchConcurrentAcrossManagersIdempotent(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawcus", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawcus": true}}
	mgrA := newTestManager(t, kit, fd)
	mgrB := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawcus",
		SessionID:  "sess-shared",
		WorkloadID: "task-shared",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}

	ids := make(chan string, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, m := range []*Manager{mgrA, mgrB} {
		wg.Add(1)
		go func(mgr *Manager) {
			defer wg.Done()
			resp, err := mgr.Launch(context.Background(), req)
			if err != nil {
				errs <- err
				return
			}
			ids <- resp.WorkerID
		}(m)
	}
	wg.Wait()
	close(ids)
	close(errs)

	for err := range errs {
		t.Fatalf("unexpected launch error: %v", err)
	}
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Fatalf("expected one worker id across managers, got %v", seen)
	}
	if fd.upCalls != 1 {
		t.Fatalf("compose up calls=%d want 1", fd.upCalls)
	}
}

func TestLaunchConcurrentUniqueSessions_NoStateLoss(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawcus", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawcus": true}}
	mgr := newTestManager(t, kit, fd)

	const n = 10
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := LaunchRequest{
				Version:    VersionV1,
				Agent:      "clawcus",
				SessionID:  fmt.Sprintf("sess-%d", i),
				WorkloadID: fmt.Sprintf("task-%d", i),
			}
			req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
			_, err := mgr.Launch(context.Background(), req)
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("unexpected launch error: %v", err)
	}

	list, err := mgr.List(context.Background())
	if err != nil {
		t.Fatalf("list workers: %v", err)
	}
	if len(list.Workers) != n {
		t.Fatalf("workers=%d want %d", len(list.Workers), n)
	}
	seenIDs := map[string]bool{}
	for _, w := range list.Workers {
		seenIDs[w.WorkerID] = true
	}
	if len(seenIDs) != n {
		t.Fatalf("unique worker ids=%d want %d", len(seenIDs), n)
	}
	if fd.upCalls != n {
		t.Fatalf("compose up calls=%d want %d", fd.upCalls, n)
	}
}

func TestLaunchConcurrentMultiAgentAttribution(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	mustCreateAgent(t, kit, "clawcus", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{
		"clawfather": true,
		"clawcus":    true,
	}}
	mgr := newTestManager(t, kit, fd)

	const perAgent = 5
	errs := make(chan error, perAgent*2)
	var wg sync.WaitGroup
	launchAgent := func(agent string) {
		for i := 0; i < perAgent; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := LaunchRequest{
					Version:    VersionV1,
					Agent:      agent,
					SessionID:  fmt.Sprintf("%s-sess-%d", agent, i),
					WorkloadID: fmt.Sprintf("%s-task-%d", agent, i),
				}
				req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
				_, err := mgr.Launch(context.Background(), req)
				if err != nil {
					errs <- err
				}
			}()
		}
	}
	launchAgent("clawfather")
	launchAgent("clawcus")
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("unexpected launch error: %v", err)
	}

	list, err := mgr.List(context.Background())
	if err != nil {
		t.Fatalf("list workers: %v", err)
	}
	if len(list.Workers) != perAgent*2 {
		t.Fatalf("workers=%d want %d", len(list.Workers), perAgent*2)
	}
	countByAgent := map[string]int{}
	for _, w := range list.Workers {
		countByAgent[w.Agent]++
	}
	if countByAgent["clawfather"] != perAgent {
		t.Fatalf("clawfather workers=%d want %d", countByAgent["clawfather"], perAgent)
	}
	if countByAgent["clawcus"] != perAgent {
		t.Fatalf("clawcus workers=%d want %d", countByAgent["clawcus"], perAgent)
	}
	if fd.upCalls != perAgent*2 {
		t.Fatalf("compose up calls=%d want %d", fd.upCalls, perAgent*2)
	}
}

func TestLaunchRejectsMountOutsideAgentPolicy(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "david-clawggins", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"david-clawggins": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "david-clawggins",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/etc:/host-etc:ro"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected mount policy denial")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodePolicyDenied {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodePolicyDenied)
	}
	if fd.upCalls != 0 {
		t.Fatalf("compose up calls=%d want 0", fd.upCalls)
	}
}

func TestLaunchComposeUpFailureCleansPartialStack(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "david-clawggins", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{
		running: map[string]bool{"david-clawggins": true},
		upErr:   errors.New("compose up failed"),
	}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "david-clawggins",
		SessionID:  "sess-up-fail",
		WorkloadID: "task-up-fail",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}

	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected compose up failure")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodeInternal {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodeInternal)
	}
	if fd.downCalls != 1 {
		t.Fatalf("compose down calls=%d want 1 cleanup after compose up failure", fd.downCalls)
	}
}

func TestLaunchPolicyDeniedLogsLaunchDeniedAudit(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "david-clawggins", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"david-clawggins": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "david-clawggins",
		SessionID:  "sess-denied",
		WorkloadID: "task-denied",
	}
	req.MountProfile.Volumes = []string{"/etc:/host-etc:ro"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected mount policy denial")
	}

	records := readAuditRecords(t, kit)
	foundDenied := false
	for _, r := range records {
		if r.Action != "worker:LaunchDenied" {
			continue
		}
		foundDenied = true
		if r.Decision != "deny" {
			t.Fatalf("decision=%q want deny", r.Decision)
		}
		if r.Agent != "david-clawggins" {
			t.Fatalf("agent=%q want david-clawggins", r.Agent)
		}
		if r.Resource != "task-denied" {
			t.Fatalf("resource=%q want task-denied", r.Resource)
		}
		if !strings.Contains(r.DenialReason, "not allowed for this agent") {
			t.Fatalf("unexpected denial reason: %q", r.DenialReason)
		}
	}
	if !foundDenied {
		t.Fatal("expected worker:LaunchDenied audit record")
	}
}

func TestLaunchRejectsSecretRefOutsideAgentPolicy(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgentWithSecrets(
		t,
		kit,
		"clawfather",
		[]string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"},
		[]string{"telegram.bot_token"},
	)
	mustDefineSecretRef(t, kit, "telegram.bot_token", "TELEGRAM_BOT_TOKEN", secrets.RoleWorker)
	mustDefineSecretRef(t, kit, "model.openrouter", "OPENROUTER_API_KEY", secrets.RoleWorker)

	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	req.SecretsProfile.Refs = []string{"model.openrouter"}

	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected secret policy denial")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodePolicyDenied {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodePolicyDenied)
	}
	if fd.upCalls != 0 {
		t.Fatalf("compose up calls=%d want 0", fd.upCalls)
	}
}

func TestLaunchRejectsUndefinedSecretRef(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgentWithSecrets(
		t,
		kit,
		"clawfather",
		[]string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"},
		[]string{"telegram.bot_token"},
	)
	// Intentionally do not define telegram.bot_token in secrets registry.

	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	req.SecretsProfile.Refs = []string{"telegram.bot_token"}

	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected undefined secret ref denial")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodePolicyDenied {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodePolicyDenied)
	}
	if !strings.Contains(apiErr.Message, "not defined") {
		t.Fatalf("unexpected error message: %q", apiErr.Message)
	}
	if fd.upCalls != 0 {
		t.Fatalf("compose up calls=%d want 0", fd.upCalls)
	}
}

func TestLaunchRejectsSecretRefNotExposedToWorkerRole(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgentWithSecrets(
		t,
		kit,
		"clawfather",
		[]string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"},
		[]string{"telegram.bot_token"},
	)
	mustDefineSecretRef(t, kit, "telegram.bot_token", "TELEGRAM_BOT_TOKEN", secrets.RoleGateway)

	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	req.SecretsProfile.Refs = []string{"telegram.bot_token"}

	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected role policy denial")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodePolicyDenied {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodePolicyDenied)
	}
	if !strings.Contains(apiErr.Message, "not exposed to role") {
		t.Fatalf("unexpected error message: %q", apiErr.Message)
	}
	if fd.upCalls != 0 {
		t.Fatalf("compose up calls=%d want 0", fd.upCalls)
	}
}

func TestLaunchStrictOpenClawRejectsNonEnforceMode(t *testing.T) {
	t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", "1")

	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManagerWithValidator(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
		Labels:     map[string]string{"source": "openclaw-gateway"},
	}
	req.NetworkProfile.Mode = "log"
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected policy denial for non-enforce mode")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodePolicyDenied {
		t.Fatalf("unexpected error: %#v", err)
	}
	if !strings.Contains(apiErr.Message, "network_profile.mode=enforce") {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
}

func TestLaunchStrictOpenClawRejectsMissingSourceLabel(t *testing.T) {
	t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", "1")

	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManagerWithValidator(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected policy denial for missing source label")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodePolicyDenied {
		t.Fatalf("unexpected error: %#v", err)
	}
	if !strings.Contains(apiErr.Message, "labels.source=openclaw-gateway") {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
}

func TestLaunchStrictOpenClawRejectsNonLeastExposure(t *testing.T) {
	t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", "1")

	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManagerWithValidator(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
		Labels:     map[string]string{"source": "openclaw-gateway"},
	}
	req.SecretsProfile.Exposure = "broad"
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected policy denial for non-least secret exposure")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodePolicyDenied {
		t.Fatalf("unexpected error: %#v", err)
	}
	if !strings.Contains(apiErr.Message, "secrets_profile.exposure=least") {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
}

func TestLaunchStrictOpenClawRejectsUnexpectedInitialScope(t *testing.T) {
	t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", "1")

	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManagerWithValidator(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
		Labels:     map[string]string{"source": "openclaw-gateway"},
	}
	req.NetworkProfile.InitialPolicyScope = "bootstrap-all"
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected policy denial for unsupported initial policy scope")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodePolicyDenied {
		t.Fatalf("unexpected error: %#v", err)
	}
	if !strings.Contains(apiErr.Message, "initial_policy_scope=existing-active") {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
}

func TestLaunchStrictOpenClawRejectsDockerSocketMount(t *testing.T) {
	t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", "1")

	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{
		"/srv/loa/resources/clawkeeper:/clawkeeper:rw",
		"/var/run/docker.sock:/var/run/docker.sock",
	})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManagerWithValidator(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
		Labels:     map[string]string{"source": "openclaw-gateway"},
	}
	req.MountProfile.Volumes = []string{"/var/run/docker.sock:/var/run/docker.sock"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected policy denial for docker socket mount in strict mode")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodePolicyDenied {
		t.Fatalf("unexpected error: %#v", err)
	}
	if !strings.Contains(apiErr.Message, "forbids mounting container runtime sockets") {
		t.Fatalf("unexpected message: %q", apiErr.Message)
	}
	if fd.upCalls != 0 {
		t.Fatalf("compose up calls=%d want 0", fd.upCalls)
	}
}

func TestLaunchPassesExplicitSecretRefsToSetup(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgentWithSecrets(
		t,
		kit,
		"clawfather",
		[]string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"},
		[]string{"telegram.bot_token"},
	)
	mustDefineSecretRef(t, kit, "telegram.bot_token", "TELEGRAM_BOT_TOKEN", secrets.RoleWorker)

	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	var captured contain.Options
	mgr.setup = func(opts contain.Options) (*contain.Environment, error) {
		captured = opts
		return &contain.Environment{
			TmpDir:      filepath.Join(kit, "tmp", "loa-contain-test"),
			ComposePath: filepath.Join(kit, "tmp", "docker-compose.yaml"),
			KitDir:      kit,
		}, nil
	}

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	req.SecretsProfile.Refs = []string{"telegram.bot_token"}

	if _, err := mgr.Launch(context.Background(), req); err != nil {
		t.Fatalf("launch: %v", err)
	}
	if captured.SecretRole != secrets.RoleWorker {
		t.Fatalf("captured secret role=%q want %q", captured.SecretRole, secrets.RoleWorker)
	}
	if !captured.UseOnlyExtraVolumes {
		t.Fatal("expected worker launch to use only explicitly requested mounts")
	}
	if len(captured.ExtraVolumes) != 1 || captured.ExtraVolumes[0] != "/srv/loa/resources/clawkeeper:/clawkeeper:rw" {
		t.Fatalf("captured extra volumes = %v", captured.ExtraVolumes)
	}
	if len(captured.SecretRefs) != 1 || captured.SecretRefs[0] != "telegram.bot_token" {
		t.Fatalf("captured secret refs = %v", captured.SecretRefs)
	}

	req2 := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-2",
		WorkloadID: "task-2",
	}
	req2.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	if _, err := mgr.Launch(context.Background(), req2); err != nil {
		t.Fatalf("launch without refs: %v", err)
	}
	if captured.SecretRefs == nil {
		t.Fatal("expected explicit empty secret refs override, got nil")
	}
	if len(captured.SecretRefs) != 0 {
		t.Fatalf("expected no secret refs for launch without refs, got %v", captured.SecretRefs)
	}
}

func TestGetNotFound(t *testing.T) {
	kit := t.TempDir()
	mgr, err := NewManager(kit)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	_, err = mgr.Get(context.Background(), "wk_missing")
	if err == nil {
		t.Fatal("expected not found error")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodeWorkerNotFound {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestGetMarksWorkerFailedWhenContainerIsGone(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawlon-musk", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawlon-musk": false}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawlon-musk",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	launch, err := mgr.Launch(context.Background(), req)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}

	got, err := mgr.Get(context.Background(), launch.WorkerID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "failed" {
		t.Fatalf("get status=%q want failed", got.Status)
	}
}

func TestTerminateWorkerNotFound(t *testing.T) {
	kit := t.TempDir()
	mgr, err := NewManager(kit)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	_, err = mgr.Terminate(context.Background(), "wk_missing", "nope")
	if err == nil {
		t.Fatal("expected not found error")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodeWorkerNotFound {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestListWorkersSorted(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	req1 := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req1.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	if _, err := mgr.Launch(context.Background(), req1); err != nil {
		t.Fatalf("launch req1: %v", err)
	}
	req2 := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-2",
		WorkloadID: "task-2",
	}
	req2.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	if _, err := mgr.Launch(context.Background(), req2); err != nil {
		t.Fatalf("launch req2: %v", err)
	}

	list, err := mgr.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Workers) != 2 {
		t.Fatalf("list workers=%d want 2", len(list.Workers))
	}
	if list.Workers[0].WorkerID > list.Workers[1].WorkerID {
		t.Fatalf("workers not sorted: %+v", list.Workers)
	}
}

func TestLaunchRejectsChildWorkerByDefault(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	parentReq := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-parent",
		WorkloadID: "task-parent",
	}
	parentReq.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	parent, err := mgr.Launch(context.Background(), parentReq)
	if err != nil {
		t.Fatalf("launch parent: %v", err)
	}
	if parent.Depth != 0 {
		t.Fatalf("parent depth=%d want 0", parent.Depth)
	}

	childReq := LaunchRequest{
		Version:        VersionV1,
		Agent:          "clawfather",
		SessionID:      "sess-child",
		WorkloadID:     "task-child",
		ParentWorkerID: parent.WorkerID,
	}
	childReq.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	_, err = mgr.Launch(context.Background(), childReq)
	if err == nil {
		t.Fatal("expected child launch to be blocked by default max depth")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodePolicyDenied {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodePolicyDenied)
	}
	if fd.upCalls != 1 {
		t.Fatalf("compose up calls=%d want 1", fd.upCalls)
	}
}

func TestLaunchAllowsChildWorkerWhenMaxDepthSet(t *testing.T) {
	t.Setenv("LOA_WORKER_MAX_DEPTH", "1")

	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	parentReq := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-parent",
		WorkloadID: "task-parent",
	}
	parentReq.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	parent, err := mgr.Launch(context.Background(), parentReq)
	if err != nil {
		t.Fatalf("launch parent: %v", err)
	}

	childReq := LaunchRequest{
		Version:        VersionV1,
		Agent:          "clawfather",
		SessionID:      "sess-child",
		WorkloadID:     "task-child",
		ParentWorkerID: parent.WorkerID,
	}
	childReq.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	child, err := mgr.Launch(context.Background(), childReq)
	if err != nil {
		t.Fatalf("launch child: %v", err)
	}
	if child.Depth != 1 {
		t.Fatalf("child depth=%d want 1", child.Depth)
	}
	if child.ParentWorkerID != parent.WorkerID {
		t.Fatalf("child parent_worker_id=%q want %q", child.ParentWorkerID, parent.WorkerID)
	}
	if fd.upCalls != 2 {
		t.Fatalf("compose up calls=%d want 2", fd.upCalls)
	}
}

func TestLaunchFailsOnInvalidMaxDepthConfig(t *testing.T) {
	t.Setenv("LOA_WORKER_MAX_DEPTH", "nope")

	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "task-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected invalid max depth config failure")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != CodeInternal {
		t.Fatalf("error code=%q want %q", apiErr.Code, CodeInternal)
	}
}

func TestLaunchSetupFailureLogsInternalError(t *testing.T) {
	kit := t.TempDir()
	mustCreateAgent(t, kit, "clawfather", []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"})
	fd := &fakeDocker{running: map[string]bool{"clawfather": true}}
	mgr := newTestManager(t, kit, fd)
	mgr.setup = func(opts contain.Options) (*contain.Environment, error) {
		return nil, errors.New("boom")
	}

	req := LaunchRequest{
		Version:    VersionV1,
		Agent:      "clawfather",
		SessionID:  "sess-1",
		WorkloadID: "tool-1",
	}
	req.MountProfile.Volumes = []string{"/srv/loa/resources/clawkeeper:/clawkeeper:rw"}
	_, err := mgr.Launch(context.Background(), req)
	if err == nil {
		t.Fatal("expected setup failure")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != CodeInternal {
		t.Fatalf("unexpected error: %#v", err)
	}

	// Ensure audit file was created and launch failure was logged.
	auditFiles, readErr := os.ReadDir(filepath.Join(kit, "audit"))
	if readErr != nil {
		t.Fatalf("read audit dir: %v", readErr)
	}
	foundJSONL := false
	for _, f := range auditFiles {
		if strings.HasSuffix(f.Name(), ".jsonl") {
			foundJSONL = true
			break
		}
	}
	if !foundJSONL {
		t.Fatalf("expected at least one audit jsonl file after launch failure")
	}
}
