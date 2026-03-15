package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marcusmom/land-of-agents/app/approval"
	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/netscope"
)

type stderrCapture struct {
	old  *os.File
	read *os.File
	send *os.File
	done chan struct{}

	mu  sync.Mutex
	buf strings.Builder
}

type stdoutCapture struct {
	old  *os.File
	read *os.File
	send *os.File
	done chan struct{}

	mu  sync.Mutex
	buf strings.Builder
}

func startStderrCapture(t *testing.T) *stderrCapture {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	c := &stderrCapture{
		old:  os.Stderr,
		read: r,
		send: w,
		done: make(chan struct{}),
	}
	os.Stderr = w
	go func() {
		defer close(c.done)
		tmp := make([]byte, 1024)
		for {
			n, err := c.read.Read(tmp)
			if n > 0 {
				c.mu.Lock()
				c.buf.Write(tmp[:n])
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *stderrCapture) Snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *stderrCapture) Stop() string {
	_ = c.send.Close()
	os.Stderr = c.old
	<-c.done
	_ = c.read.Close()
	return c.Snapshot()
}

func startStdoutCapture(t *testing.T) *stdoutCapture {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	c := &stdoutCapture{
		old:  os.Stdout,
		read: r,
		send: w,
		done: make(chan struct{}),
	}
	os.Stdout = w
	go func() {
		defer close(c.done)
		tmp := make([]byte, 1024)
		for {
			n, err := c.read.Read(tmp)
			if n > 0 {
				c.mu.Lock()
				c.buf.Write(tmp[:n])
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *stdoutCapture) Snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *stdoutCapture) Stop() string {
	_ = c.send.Close()
	os.Stdout = c.old
	<-c.done
	_ = c.read.Close()
	return c.Snapshot()
}

func withStdinSequence(t *testing.T, delay time.Duration, lines ...string) func() {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe for stdin sequence: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, line := range lines {
			if i > 0 && delay > 0 {
				time.Sleep(delay)
			}
			if _, err := io.WriteString(w, strings.TrimSpace(line)+"\n"); err != nil {
				break
			}
		}
		_ = w.Close()
	}()
	return func() {
		os.Stdin = old
		_ = r.Close()
		<-done
	}
}

func TestApplyNetworkScope_Domain(t *testing.T) {
	prop := approval.ProposalWithCedar{
		Description: "hackerman can make HTTP requests to http-intake.logs.us5.datadoghq.com",
		Agent:       "hackerman",
		Filename:    "hackerman-http-request-http-intake-logs-us5-datadoghq-com.cedar",
		Cedar: `permit(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"http-intake.logs.us5.datadoghq.com"
);`,
	}
	denials := []audit.Record{{
		Action:   "http:Request",
		Resource: "http-intake.logs.us5.datadoghq.com",
	}}

	got := applyNetworkScope(prop, denials, approval.NetworkScopeDomain)
	if strings.Contains(got.Cedar, "http-intake.logs.us5.datadoghq.com") {
		t.Fatalf("expected host to be generalized in cedar: %s", got.Cedar)
	}
	if !strings.Contains(got.Cedar, `Resource::"datadoghq.com"`) {
		t.Fatalf("expected datadoghq.com in cedar: %s", got.Cedar)
	}
	if !strings.Contains(got.Description, "datadoghq.com") {
		t.Fatalf("expected datadoghq.com in description: %s", got.Description)
	}
}

func TestRewriteForbidPolicy(t *testing.T) {
	prop := approval.ProposalWithCedar{
		Agent:    "hackerman",
		Filename: "hackerman-http-news-yahoo-com.cedar",
		Cedar: `permit(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"news.yahoo.com"
);`,
	}
	got := rewriteForbidPolicy(prop)
	if strings.Contains(got.Cedar, "permit(") {
		t.Fatalf("expected permit to be rewritten: %s", got.Cedar)
	}
	if !strings.Contains(got.Cedar, "forbid(") {
		t.Fatalf("expected forbid in cedar: %s", got.Cedar)
	}
	if got.Filename != "hackerman-http-news-yahoo-com-forbid.cedar" {
		t.Fatalf("unexpected filename: %s", got.Filename)
	}
}

func TestNormalizeHost(t *testing.T) {
	if got := netscope.NormalizeHost("https://api.wrike.com:443/tasks"); got != "api.wrike.com" {
		t.Fatalf("normalizeHost url: got %q", got)
	}
	if got := netscope.NormalizeHost("api.wrike.com:443"); got != "api.wrike.com" {
		t.Fatalf("normalizeHost host:port: got %q", got)
	}
}

func TestEffectiveDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{host: "news.google.com", want: "google.com"},
		{host: "raw.githubusercontent.com", want: "githubusercontent.com"},
		{host: "example.com", want: "example.com"},
	}
	for _, tt := range tests {
		if got := netscope.EffectiveDomain(tt.host); got != tt.want {
			t.Fatalf("EffectiveDomain(%q)=%q want %q", tt.host, got, tt.want)
		}
	}
}

func TestParseMountSpec(t *testing.T) {
	tests := []struct {
		spec          string
		wantHost      string
		wantContainer string
		wantMode      string
	}{
		{spec: "/a:/b", wantHost: "/a", wantContainer: "/b", wantMode: "rw"},
		{spec: "/a:/b:ro", wantHost: "/a", wantContainer: "/b", wantMode: "ro"},
		{spec: "/a:/b:rw", wantHost: "/a", wantContainer: "/b", wantMode: "rw"},
	}
	for _, tt := range tests {
		h, c, m := parseMountSpec(tt.spec)
		if h != tt.wantHost || c != tt.wantContainer || m != tt.wantMode {
			t.Fatalf("parseMountSpec(%q)=(%q,%q,%q) want (%q,%q,%q)", tt.spec, h, c, m, tt.wantHost, tt.wantContainer, tt.wantMode)
		}
	}
}

func TestRememberedVolumeForCWD(t *testing.T) {
	vols := []string{
		"/Users/marcus/project-a:/workspace/project-a:ro",
		"/Users/marcus/project-b:/workspace/project-b",
	}
	if got := rememberedVolumeForCWD(vols, "/Users/marcus/project-b"); got != vols[1] {
		t.Fatalf("rememberedVolumeForCWD got %q want %q", got, vols[1])
	}
}

func TestDecisionPathLabel_PolicyDenyCaseInsensitive(t *testing.T) {
	if got := decisionPathLabel("policy", " Deny "); got != "blocked by policy" {
		t.Fatalf("decisionPathLabel(policy, deny) = %q, want blocked by policy", got)
	}
}

func TestDecisionPathLabel_PolicyPermitCaseInsensitive(t *testing.T) {
	if got := decisionPathLabel("policy", " PERMIT "); got != "allowed by policy" {
		t.Fatalf("decisionPathLabel(policy, permit) = %q, want allowed by policy", got)
	}
}

func TestWatchDecisionLabel_NoPolicyDeny(t *testing.T) {
	got := watchDecisionLabel(audit.Record{
		Decision:     "deny",
		DecisionPath: "policy",
		DenialReason: "No policy permits hackerman to reach news.yahoo.com",
	})
	if got != "blocked since no policy exists" {
		t.Fatalf("watchDecisionLabel(no policy deny) = %q, want blocked since no policy exists", got)
	}
}

func TestWatchDecisionLabel_PolicyForbidDeny(t *testing.T) {
	got := watchDecisionLabel(audit.Record{
		Decision:     "deny",
		DecisionPath: "policy",
		DenialReason: "blocked by explicit forbid policy",
	})
	if got != "blocked by policy" {
		t.Fatalf("watchDecisionLabel(forbid deny) = %q, want blocked by policy", got)
	}
}

func TestRunWatchLoop_VerboseShowsShellCommandEvents(t *testing.T) {
	kit := t.TempDir()
	auditDir := filepath.Join(kit, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("mkdir audit: %v", err)
	}
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}

	cap := startStderrCapture(t)
	defer cap.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchLoop(ctx, watchLoopConfig{
			KitDir:      kit,
			AgentName:   "hackerman",
			Verbose:     true,
			Inline:      false,
			PrintHeader: false,
		})
	}()

	// Let watcher initialize offsets before writing the record.
	time.Sleep(120 * time.Millisecond)

	if err := logger.Log(audit.Record{
		Agent:        "hackerman",
		Scope:        "hackerman",
		Action:       "exec:Run",
		Resource:     "ls",
		Decision:     "permit",
		DecisionPath: "policy",
		Context: map[string]any{
			"command": "ls -la",
		},
	}); err != nil {
		t.Fatalf("log audit record: %v", err)
	}

	deadline := time.Now().Add(8 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		out := cap.Snapshot()
		if strings.Contains(out, "hackerman exec:Run -> ls [allowed by policy]") {
			found = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Fatalf("watch output did not include exec command event; output:\n%s", cap.Snapshot())
	}

	cancel()
	if err := <-errCh; err != nil && err != context.Canceled {
		t.Fatalf("runWatchLoop returned error: %v", err)
	}
}

func TestRunWatchLoop_VerboseShowsLSAndGrepShellEvents(t *testing.T) {
	kit := t.TempDir()
	auditDir := filepath.Join(kit, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("mkdir audit: %v", err)
	}
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}

	cap := startStderrCapture(t)
	defer cap.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchLoop(ctx, watchLoopConfig{
			KitDir:      kit,
			AgentName:   "hackerman",
			Verbose:     true,
			PrintHeader: false,
		})
	}()

	time.Sleep(120 * time.Millisecond)

	write := func(resource, cmd string) {
		t.Helper()
		if err := logger.Log(audit.Record{
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "exec:Run",
			Resource:     resource,
			Decision:     "permit",
			DecisionPath: "shell_observe",
			Context: map[string]any{
				"command": cmd,
			},
		}); err != nil {
			t.Fatalf("log audit record: %v", err)
		}
	}

	write("ls", "ls -la")
	write("grep", "grep -R TODO .")

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		out := cap.Snapshot()
		if strings.Contains(out, "hackerman exec:Run -> ls [activity observed]") &&
			strings.Contains(out, "hackerman exec:Run -> grep [activity observed]") {
			cancel()
			if err := <-errCh; err != nil && err != context.Canceled {
				t.Fatalf("runWatchLoop returned error: %v", err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("watch output missing ls/grep shell events; output:\n%s", cap.Snapshot())
}

func TestRunWatchLoop_RepeatedApprovals_NoStall(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("ANTHROPIC_API_KEY", "")
	auditDir := filepath.Join(kit, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("mkdir audit: %v", err)
	}
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}

	restoreStdin := withStdinSequence(t, 4*time.Second, "3", "3")
	defer restoreStdin()

	cap := startStderrCapture(t)
	defer cap.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchLoop(ctx, watchLoopConfig{
			KitDir:      kit,
			AgentName:   "hackerman",
			Verbose:     false,
			Inline:      false,
			PrintHeader: false,
		})
	}()

	time.Sleep(120 * time.Millisecond)
	now := time.Now().UTC()
	denials := []audit.Record{
		{
			ID:           "AUD-REPEAT-1",
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "http:Request",
			Resource:     "news.google.com",
			Decision:     "deny",
			DecisionPath: "policy",
			DenialReason: "No policy permits hackerman to reach news.google.com",
			Timestamp:    now,
		},
		{
			ID:           "AUD-REPEAT-2",
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "http:Request",
			Resource:     "news.yahoo.com",
			Decision:     "deny",
			DecisionPath: "policy",
			DenialReason: "No policy permits hackerman to reach news.yahoo.com",
			Timestamp:    now.Add(200 * time.Millisecond),
		},
	}
	for _, d := range denials {
		if err := logger.Log(d); err != nil {
			t.Fatalf("log deny: %v", err)
		}
	}

	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		out := cap.Snapshot()
		if strings.Contains(out, "news.google.com") &&
			strings.Contains(out, "news.yahoo.com") &&
			strings.Count(out, "Applying saved policy...") >= 2 {
			cancel()
			if err := <-errCh; err != nil && err != context.Canceled {
				t.Fatalf("runWatchLoop returned error: %v", err)
			}
			activeDir := filepath.Join(kit, "policies", "active")
			entries, err := os.ReadDir(activeDir)
			if err != nil {
				t.Fatalf("read active policies: %v", err)
			}
			if len(entries) < 2 {
				t.Fatalf("expected at least 2 active policies, got %d", len(entries))
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("watch output missing repeated approval progression; output:\n%s", cap.Snapshot())
}

func TestRunWatchLoop_ConcurrentFilteredWatchers(t *testing.T) {
	kit := t.TempDir()
	auditDir := filepath.Join(kit, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("mkdir audit: %v", err)
	}
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}

	cap := startStderrCapture(t)
	defer cap.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() {
		errA <- runWatchLoop(ctx, watchLoopConfig{
			KitDir:      kit,
			AgentName:   "hackerman",
			Verbose:     true,
			PrintHeader: false,
		})
	}()
	go func() {
		errB <- runWatchLoop(ctx, watchLoopConfig{
			KitDir:      kit,
			AgentName:   "clawfather",
			Verbose:     true,
			PrintHeader: false,
		})
	}()

	time.Sleep(120 * time.Millisecond)

	if err := logger.Log(audit.Record{
		ID:           "AUD-CONC-1",
		Agent:        "hackerman",
		Scope:        "hackerman",
		Action:       "http:Request",
		Resource:     "api.anthropic.com",
		Decision:     "permit",
		DecisionPath: "policy",
	}); err != nil {
		t.Fatalf("log hackerman record: %v", err)
	}
	if err := logger.Log(audit.Record{
		ID:           "AUD-CONC-2",
		Agent:        "clawfather",
		Scope:        "clawfather",
		Action:       "http:Request",
		Resource:     "news.google.com",
		Decision:     "permit",
		DecisionPath: "policy",
	}); err != nil {
		t.Fatalf("log clawfather record: %v", err)
	}

	wantA := "hackerman http:Request -> api.anthropic.com [allowed by policy]"
	wantB := "clawfather http:Request -> news.google.com [allowed by policy]"
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out := cap.Snapshot()
		if strings.Contains(out, wantA) && strings.Contains(out, wantB) {
			cancel()
			if err := <-errA; err != nil && err != context.Canceled {
				t.Fatalf("watch loop A returned error: %v", err)
			}
			if err := <-errB; err != nil && err != context.Canceled {
				t.Fatalf("watch loop B returned error: %v", err)
			}
			if strings.Count(out, wantA) != 1 {
				t.Fatalf("expected exactly one event for watcher A, got %d:\n%s", strings.Count(out, wantA), out)
			}
			if strings.Count(out, wantB) != 1 {
				t.Fatalf("expected exactly one event for watcher B, got %d:\n%s", strings.Count(out, wantB), out)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("concurrent watcher output missing expected events; output:\n%s", cap.Snapshot())
}

func TestPrintWatchEvents_LongShellCommandDoesNotFloodOutput(t *testing.T) {
	cap := startStderrCapture(t)

	longLine := strings.Repeat("x", 600)
	longScript := "bash -lc 'echo start\n" + longLine + "\n" + longLine + "\n" + longLine + "'"
	printWatchEvents([]audit.Record{{
		Agent:        "hackerman",
		Action:       "exec:Run",
		Resource:     "bash",
		Decision:     "permit",
		DecisionPath: "shell_observe",
		Context: map[string]any{
			"command": longScript,
		},
	}})

	out := cap.Stop()
	if !strings.Contains(out, "hackerman exec:Run -> bash [activity observed]") {
		t.Fatalf("missing shell event summary:\n%s", out)
	}
	if strings.Contains(out, longLine) {
		t.Fatalf("long inline shell script leaked into watch output:\n%s", out)
	}
}

func TestIsNoPolicyDenialReason(t *testing.T) {
	if !isNoPolicyDenialReason("No policy permits hackerman to reach news.yahoo.com") {
		t.Fatal("expected no-policy reason to match")
	}
	if isNoPolicyDenialReason("blocked by explicit forbid policy") {
		t.Fatal("did not expect explicit policy deny to match no-policy reason")
	}
}

func TestPolicyEffectFromCedar(t *testing.T) {
	tests := []struct {
		name  string
		cedar string
		want  string
	}{
		{
			name: "permit",
			cedar: `permit(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"news.google.com"
);`,
			want: "allow",
		},
		{
			name: "forbid",
			cedar: `forbid(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"news.yahoo.com"
);`,
			want: "deny",
		},
		{
			name:  "unknown",
			cedar: `// comment only`,
			want:  "unknown",
		},
	}

	for _, tt := range tests {
		got := policyEffectFromCedar(tt.cedar)
		if got != tt.want {
			t.Fatalf("%s: policyEffectFromCedar() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestReadActivePolicyInfoAndCounts(t *testing.T) {
	kit := t.TempDir()
	activeDir := filepath.Join(kit, "policies", "active")
	if err := os.MkdirAll(activeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(activeDir, "all-http-news-yahoo-com.cedar"), []byte(`forbid(principal, action, resource);`), 0o644); err != nil {
		t.Fatalf("WriteFile all policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(activeDir, "hackerman-http-news-google-com.cedar"), []byte(`permit(principal, action, resource);`), 0o644); err != nil {
		t.Fatalf("WriteFile agent policy: %v", err)
	}
	info := readActivePolicyInfo(kit, []string{
		"all-http-news-yahoo-com.cedar",
		"hackerman-http-news-google-com.cedar",
		"missing.cedar",
	})
	if len(info) != 3 {
		t.Fatalf("readActivePolicyInfo len=%d, want 3", len(info))
	}
	allScope, agentScope := countPolicyScopes(info)
	if allScope != 1 || agentScope != 2 {
		t.Fatalf("countPolicyScopes=(%d,%d), want (1,2)", allScope, agentScope)
	}
	allow, deny, unknown := countPolicyEffects(info)
	if allow != 1 || deny != 1 || unknown != 1 {
		t.Fatalf("countPolicyEffects=(%d,%d,%d), want (1,1,1)", allow, deny, unknown)
	}

	agentOnly := filterPolicyScope(info, "agent")
	if len(agentOnly) != 2 {
		t.Fatalf("filterPolicyScope(agent) len=%d, want 2", len(agentOnly))
	}
}

func TestPolicyScopeForAgent(t *testing.T) {
	tests := []struct {
		name       string
		policyName string
		agent      string
		wantScope  string
		wantApply  bool
	}{
		{name: "all scope", policyName: "all-http-news-yahoo-com.cedar", agent: "hackerman", wantScope: "all", wantApply: true},
		{name: "agent scope", policyName: "hackerman-http-news-google-com.cedar", agent: "hackerman", wantScope: "agent", wantApply: true},
		{name: "runtime scope", policyName: "_runtime-hackerman.cedar", agent: "hackerman", wantScope: "agent", wantApply: true},
		{name: "other agent", policyName: "goggins-http-news-google-com.cedar", agent: "hackerman", wantScope: "", wantApply: false},
	}
	for _, tt := range tests {
		gotScope, gotApply := policyScopeForAgent(tt.policyName, tt.agent)
		if gotScope != tt.wantScope || gotApply != tt.wantApply {
			t.Fatalf("%s: policyScopeForAgent(%q,%q)=(%q,%v), want (%q,%v)", tt.name, tt.policyName, tt.agent, gotScope, gotApply, tt.wantScope, tt.wantApply)
		}
	}
}

func TestExtractCedarRules(t *testing.T) {
	cedar := `permit(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"news.google.com"
);

forbid(
  principal,
  action == Action::"http:Request",
  resource == Resource::"yahoo.com"
);`
	got := extractCedarRules(cedar)
	if len(got) != 2 {
		t.Fatalf("extractCedarRules len=%d, want 2", len(got))
	}
	if got[0].Effect != "allow" || got[0].Action != "http:Request" || got[0].Resource != "news.google.com" {
		t.Fatalf("unexpected first rule: %+v", got[0])
	}
	if got[1].Effect != "deny" || got[1].Action != "http:Request" || got[1].Resource != "yahoo.com" {
		t.Fatalf("unexpected second rule: %+v", got[1])
	}
}

func TestLoadEffectivePolicyEntries(t *testing.T) {
	kit := t.TempDir()
	if err := os.MkdirAll(filepath.Join(kit, "config"), 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(kit, "policies", "active"), 0o755); err != nil {
		t.Fatalf("mkdir policies/active: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kit, "config", "always-allowed.cedar"), []byte(`permit(principal, action == Action::"fs:Read", resource);`), 0o644); err != nil {
		t.Fatalf("write always-allowed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kit, "policies", "active", "all-http-news-yahoo-com.cedar"), []byte(`forbid(principal, action == Action::"http:Request", resource == Resource::"yahoo.com");`), 0o644); err != nil {
		t.Fatalf("write all policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kit, "policies", "active", "hackerman-http-news-google-com.cedar"), []byte(`permit(principal == Agent::"hackerman", action == Action::"http:Request", resource == Resource::"news.google.com");`), 0o644); err != nil {
		t.Fatalf("write agent policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kit, "policies", "active", "goggins-http-news-google-com.cedar"), []byte(`permit(principal == Agent::"goggins", action == Action::"http:Request", resource == Resource::"news.google.com");`), 0o644); err != nil {
		t.Fatalf("write other policy: %v", err)
	}

	entries, err := loadEffectivePolicyEntries(kit, "hackerman")
	if err != nil {
		t.Fatalf("loadEffectivePolicyEntries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries len=%d, want 3", len(entries))
	}

	allow, deny, unknown := countEffectiveEntryEffects(entries)
	if allow != 2 || deny != 1 || unknown != 0 {
		t.Fatalf("countEffectiveEntryEffects=(%d,%d,%d), want (2,1,0)", allow, deny, unknown)
	}

	netAllow, netDeny := collectNetworkEffective(entries)
	if len(netAllow) != 1 || netAllow[0] != "news.google.com" {
		t.Fatalf("net allow mismatch: %+v", netAllow)
	}
	if len(netDeny) != 1 || netDeny[0] != "yahoo.com (all agents)" {
		t.Fatalf("net deny mismatch: %+v", netDeny)
	}
}

func TestIsDeniedRecord_CaseInsensitive(t *testing.T) {
	in := []audit.Record{
		{Decision: "permit", Action: "http:Request", Resource: "api.anthropic.com"},
		{Decision: " deny ", Action: "http:Request", Resource: "news.yahoo.com"},
		{Decision: "DENY", Action: "fs:Read", Resource: "/workspace/main.go"},
	}
	var got []audit.Record
	for _, r := range in {
		if isDeniedRecord(r) {
			got = append(got, r)
		}
	}
	if len(got) != 2 {
		t.Fatalf("isDeniedRecord filtered len = %d, want 2", len(got))
	}
	if got[0].Resource != "news.yahoo.com" || got[1].Resource != "/workspace/main.go" {
		t.Fatalf("isDeniedRecord order/content mismatch: %+v", got)
	}
}

func TestDeduplicateDeniedRecords(t *testing.T) {
	in := []audit.Record{
		{Decision: "deny", Agent: "hackerman", Action: "http:Request", Resource: "news.yahoo.com"},
		{Decision: "DENY", Agent: "hackerman", Action: "http:Request", Resource: "news.yahoo.com"},
		{Decision: "deny", Agent: "hackerman", Action: "http:Request", Resource: "news.google.com"},
		{Decision: "permit", Agent: "hackerman", Action: "http:Request", Resource: "api.anthropic.com"},
	}
	got := deduplicateDeniedRecords(in)
	if len(got) != 2 {
		t.Fatalf("deduplicateDeniedRecords len = %d, want 2", len(got))
	}
	if got[0].Resource != "news.yahoo.com" || got[1].Resource != "news.google.com" {
		t.Fatalf("deduplicateDeniedRecords order/content mismatch: %+v", got)
	}
}

func TestPartitionFilesystemDenials(t *testing.T) {
	in := []audit.Record{
		{Action: "fs:Read", Resource: "/workspace/main.go"},
		{Action: "http:Request", Resource: "news.google.com"},
		{Action: "fs:Write", Resource: "/workspace/out.txt"},
	}
	fsDenials, other := partitionFilesystemDenials(in)
	if len(fsDenials) != 2 {
		t.Fatalf("fsDenials len = %d, want 2", len(fsDenials))
	}
	if len(other) != 1 || other[0].Action != "http:Request" {
		t.Fatalf("other mismatch: %+v", other)
	}
}

func TestSuggestedContainerMountTarget(t *testing.T) {
	tests := []struct {
		resource string
		want     string
	}{
		{resource: "/workspace/loa/main.go", want: "/workspace/loa"},
		{resource: "/workspace/data", want: "/workspace/data"},
		{resource: "news.google.com", want: ""},
		{resource: "", want: ""},
	}
	for _, tt := range tests {
		if got := suggestedContainerMountTarget(tt.resource); got != tt.want {
			t.Fatalf("suggestedContainerMountTarget(%q) = %q, want %q", tt.resource, got, tt.want)
		}
	}
}

func TestActivateApprovedProposal_AllAgentsDomain(t *testing.T) {
	kit := t.TempDir()
	for _, sub := range []string{"config", "policies", "policies/active", "audit"} {
		if err := os.MkdirAll(filepath.Join(kit, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	if err := os.WriteFile(filepath.Join(kit, "config", "always-allowed.cedar"), []byte(`permit(principal, action == Action::"fs:Read", resource);`), 0o644); err != nil {
		t.Fatalf("write always-allowed: %v", err)
	}

	pipeline := approval.NewPipeline(approval.PipelineConfig{KitDir: kit})
	prop := approval.ProposalWithCedar{
		Description: "hackerman can make HTTP requests to news.ycombinator.com",
		Reasoning:   "test",
		Agent:       "hackerman",
		DenialIDs:   []string{"AUD-1"},
		Cedar: `permit(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"news.ycombinator.com"
);`,
		Filename: "hackerman-http-Request-news-ycombinator-com.cedar",
	}
	covered := []audit.Record{
		{
			ID:       "AUD-1",
			Agent:    "hackerman",
			Action:   "http:Request",
			Resource: "news.ycombinator.com",
			Decision: "deny",
		},
	}
	decision := approval.PromptResult{
		Decision:     approval.Approved,
		Scope:        approval.AllAgents,
		NetworkScope: approval.NetworkScopeDomain,
		Effect:       approval.PolicyPermit,
	}

	msg, err := activateApprovedProposal(pipeline, prop, covered, decision)
	if err != nil {
		t.Fatalf("activateApprovedProposal: %v", err)
	}
	if !strings.Contains(msg, "Approved for all agents") {
		t.Fatalf("unexpected message: %q", msg)
	}

	entries, err := os.ReadDir(filepath.Join(kit, "policies", "active"))
	if err != nil {
		t.Fatalf("readdir active: %v", err)
	}
	var cedarFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".cedar") {
			cedarFiles = append(cedarFiles, e.Name())
		}
	}
	if len(cedarFiles) == 0 {
		t.Fatalf("expected at least one active cedar file, got none")
	}
	data, err := os.ReadFile(filepath.Join(kit, "policies", "active", cedarFiles[0]))
	if err != nil {
		t.Fatalf("read active policy: %v", err)
	}
	policy := string(data)
	if !strings.Contains(policy, `Resource::"ycombinator.com"`) {
		t.Fatalf("expected domain-scoped resource in active policy, got:\n%s", policy)
	}
	if strings.Contains(policy, `principal == Agent::"hackerman"`) {
		t.Fatalf("expected all-agents principal rewrite, got:\n%s", policy)
	}
	if !strings.Contains(policy, "permit(") {
		t.Fatalf("expected permit policy, got:\n%s", policy)
	}
}

func TestParseCWDMountChoice(t *testing.T) {
	tests := []struct {
		in        string
		want      cwdMountChoice
		wantValid bool
	}{
		{in: "1", want: cwdMountChoice{readOnly: true, remember: true}, wantValid: true},
		{in: "2", want: cwdMountChoice{readOnly: true, remember: true, allAgents: true}, wantValid: true},
		{in: "3", want: cwdMountChoice{remember: true}, wantValid: true},
		{in: "4", want: cwdMountChoice{remember: true, allAgents: true}, wantValid: true},
		{in: "5", want: cwdMountChoice{skip: true, never: true}, wantValid: true},
		{in: "6", want: cwdMountChoice{skip: true, never: true, allAgents: true}, wantValid: true},
		{in: "7", want: cwdMountChoice{skip: true}, wantValid: true},
		{in: "8", want: cwdMountChoice{readOnly: true}, wantValid: true},
		{in: "9", want: cwdMountChoice{}, wantValid: true},
		{in: "", want: cwdMountChoice{skip: true}, wantValid: true},
		{in: "no", want: cwdMountChoice{skip: true}, wantValid: true},
		{in: "0", want: cwdMountChoice{}, wantValid: false},
		{in: "wat", want: cwdMountChoice{}, wantValid: false},
	}
	for _, tt := range tests {
		got, ok := parseCWDMountChoice(tt.in)
		if ok != tt.wantValid {
			t.Fatalf("parseCWDMountChoice(%q) valid=%v, want %v", tt.in, ok, tt.wantValid)
		}
		if !ok {
			continue
		}
		if got != tt.want {
			t.Fatalf("parseCWDMountChoice(%q)=%+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestParseTerminateAgent(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{name: "flag", args: []string{"--agent", "hackerman19"}, want: "hackerman19"},
		{name: "positional", args: []string{"hackerman19"}, want: "hackerman19"},
		{name: "flag overrides positional", args: []string{"hackerman", "--agent", "hackerman19"}, want: "hackerman19"},
		{name: "missing", args: []string{}, wantErr: true},
		{name: "bad flag", args: []string{"--wat"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTerminateAgent(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (value=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShellResourceFromCommand(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "ls -la", want: "ls"},
		{in: "grep -R TODO .", want: "grep"},
		{in: "FOO=bar /usr/bin/grep x y", want: "grep"},
		{in: "command -v loa", want: "loa"},
		{in: "", want: "_"},
		{in: "A=1 B=2", want: "_"},
	}
	for _, tt := range tests {
		if got := shellResourceFromCommand(tt.in); got != tt.want {
			t.Fatalf("shellResourceFromCommand(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestHasNeverMountDir(t *testing.T) {
	dirs := []string{"/Users/marcus/project", "/tmp/foo/"}
	if !hasNeverMountDir(dirs, "/Users/marcus/project") {
		t.Fatal("expected exact never-mount directory match")
	}
	if !hasNeverMountDir(dirs, "/tmp/foo") {
		t.Fatal("expected cleaned never-mount directory match")
	}
	if hasNeverMountDir(dirs, "/Users/marcus/other") {
		t.Fatal("did not expect unrelated directory to match")
	}
}

func TestKitDir_UsesEnv(t *testing.T) {
	t.Setenv("LOA_KIT", "/tmp/custom-loa-kit")
	if got := kitDir(); got != "/tmp/custom-loa-kit" {
		t.Fatalf("kitDir()=%q want /tmp/custom-loa-kit", got)
	}
}

func TestKitDir_DefaultsToHome(t *testing.T) {
	t.Setenv("LOA_KIT", "")
	t.Setenv("HOME", "/tmp/loa-home")
	if got := kitDir(); got != "/tmp/loa-home/land-of-agents" {
		t.Fatalf("kitDir()=%q want /tmp/loa-home/land-of-agents", got)
	}
}

func TestInlineUnsupportedReason_ClaudeRuntime(t *testing.T) {
	reason, unsupported := inlineUnsupportedReason(agent.Agent{Runtime: "claude-code"})
	if !unsupported {
		t.Fatal("expected claude runtime to be unsupported for inline")
	}
	if !strings.Contains(reason, "claude-code") {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestInlineUnsupportedReason_NonClaudeRuntime(t *testing.T) {
	_, unsupported := inlineUnsupportedReason(agent.Agent{Runtime: "codex"})
	if unsupported {
		t.Fatal("did not expect codex runtime to be unsupported for inline")
	}
}

func TestIsOpenClawRuntime(t *testing.T) {
	if !isOpenClawRuntime(agent.Agent{Runtime: "openclaw"}) {
		t.Fatal("expected openclaw runtime to be detected")
	}
	if isOpenClawRuntime(agent.Agent{Runtime: "claude-code"}) {
		t.Fatal("did not expect non-openclaw runtime to match")
	}
}

func TestOpenclawRequireWorkerAPI(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"1", true},
		{"true", true},
		{"yes", true},
		{"on", true},
	}
	for _, tt := range tests {
		t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", tt.val)
		if got := openclawRequireWorkerAPI(); got != tt.want {
			t.Fatalf("openclawRequireWorkerAPI(%q)=%v want %v", tt.val, got, tt.want)
		}
	}
}

func TestValidateOpenClawBackend(t *testing.T) {
	openclaw := agent.Agent{Runtime: "openclaw"}
	claude := agent.Agent{Runtime: "claude-code"}
	launcher := filepath.Join(t.TempDir(), "openclaw-worker-launcher.sh")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write launcher: %v", err)
	}

	t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", "0")
	t.Setenv("WORKER_BACKEND", "docker")
	t.Setenv("OPENCLAW_WORKER_LAUNCHER", "")
	if err := validateOpenClawBackend(openclaw); err != nil {
		t.Fatalf("expected no error when strict mode disabled, got %v", err)
	}

	t.Setenv("LOA_OPENCLAW_REQUIRE_WORKER_API", "1")
	t.Setenv("WORKER_BACKEND", "loa")
	t.Setenv("OPENCLAW_WORKER_LAUNCHER", launcher)
	if err := validateOpenClawBackend(openclaw); err != nil {
		t.Fatalf("expected no error for strict openclaw prereqs, got %v", err)
	}

	t.Setenv("WORKER_BACKEND", "")
	if err := validateOpenClawBackend(openclaw); err == nil {
		t.Fatal("expected error when backend missing in strict mode")
	}

	t.Setenv("WORKER_BACKEND", "docker")
	if err := validateOpenClawBackend(openclaw); err == nil {
		t.Fatal("expected error when backend is docker in strict mode")
	}

	t.Setenv("WORKER_BACKEND", "loa")
	t.Setenv("OPENCLAW_WORKER_LAUNCHER", "")
	if err := validateOpenClawBackend(openclaw); err == nil {
		t.Fatal("expected error when launcher is missing in strict mode")
	}

	t.Setenv("WORKER_BACKEND", "")
	if err := validateOpenClawBackend(claude); err != nil {
		t.Fatalf("did not expect error for non-openclaw runtime: %v", err)
	}

	openclawSocket := agent.Agent{
		Runtime: "openclaw",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	}
	t.Setenv("WORKER_BACKEND", "loa")
	t.Setenv("OPENCLAW_WORKER_LAUNCHER", launcher)
	if err := validateOpenClawBackend(openclawSocket); err == nil {
		t.Fatal("expected error when docker socket mount is present in strict mode")
	}
}

func TestRunWatchLoop_VerboseAllAgentsShowsMultipleAgents(t *testing.T) {
	kit := t.TempDir()
	auditDir := filepath.Join(kit, "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		t.Fatalf("mkdir audit: %v", err)
	}
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}

	cap := startStderrCapture(t)
	defer cap.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runWatchLoop(ctx, watchLoopConfig{
			KitDir:      kit,
			AgentName:   "",
			Verbose:     true,
			Inline:      false,
			PrintHeader: false,
		})
	}()

	time.Sleep(120 * time.Millisecond)

	if err := logger.Log(audit.Record{
		Agent:        "hackerman",
		Scope:        "hackerman",
		Action:       "http:Request",
		Resource:     "news.google.com",
		Decision:     "permit",
		DecisionPath: "policy",
	}); err != nil {
		t.Fatalf("log hackerman record: %v", err)
	}
	if err := logger.Log(audit.Record{
		Agent:        "clawfather",
		Scope:        "clawfather",
		Action:       "http:Request",
		Resource:     "news.yahoo.com",
		Decision:     "deny",
		DecisionPath: "policy",
		DenialReason: "No policy permits clawfather to reach news.yahoo.com",
	}); err != nil {
		t.Fatalf("log clawfather record: %v", err)
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		out := cap.Snapshot()
		if strings.Contains(out, "hackerman http:Request -> news.google.com [allowed by policy]") &&
			strings.Contains(out, "clawfather http:Request -> news.yahoo.com [blocked since no policy exists]") {
			cancel()
			if err := <-errCh; err != nil && err != context.Canceled {
				t.Fatalf("runWatchLoop returned error: %v", err)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("watch output missing multi-agent events; output:\n%s", cap.Snapshot())
}

func TestRunDoctorSummaryOutput(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)

	runInit(nil)

	mgr := agent.NewManager(kit)
	if err := mgr.Create("hackerman", agent.CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	activeDir := filepath.Join(kit, "policies", "active")
	if err := os.WriteFile(filepath.Join(activeDir, "hackerman-http-Request-news-google-com.cedar"), []byte(`permit(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"news.google.com"
);`), 0o644); err != nil {
		t.Fatalf("write active policy: %v", err)
	}

	cap := startStdoutCapture(t)
	runDoctor([]string{"--agent", "hackerman"})
	out := cap.Stop()

	checks := []string{
		"🩺 LOA Doctor: hackerman",
		"Overall:",
		"✅ Health",
		"🏠 LOA Home",
		"🤖 Agent",
		"🧱 Containment",
		"🔐 Secrets & Auth",
		"📜 Activity (Audit Log)",
		"🛡 Policies (Active)",
		"🐳 Runtime",
		"📁 Data Sources",
		"Tip: run 'loa doctor --verbose --agent hackerman' for full diagnostics.",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("doctor output missing %q:\n%s", c, out)
		}
	}
}

func TestRunDoctorSummaryOutput_DegradedKit(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)

	cap := startStdoutCapture(t)
	runDoctor(nil)
	out := cap.Stop()

	checks := []string{
		"Overall: ⚠️  Attention needed",
		"Status: ATTENTION",
		"Layout: MISSING",
		"Fix: run 'loa init'",
		"Tip: run 'loa doctor --verbose",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("doctor degraded output missing %q:\n%s", c, out)
		}
	}
}

func TestRunDoctorSummaryOutput_MissingAgent(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)

	runInit(nil)

	cap := startStdoutCapture(t)
	runDoctor([]string{"--agent", "missing-agent"})
	out := cap.Stop()

	checks := []string{
		"🩺 LOA Doctor: missing-agent",
		"Overall: ⚠️  Attention needed",
		"Summary: agent \"missing-agent\" not found",
		"Name: missing-agent",
		"Status: NOT FOUND",
		"🛡 Policies (Active)",
		"Total affecting missing-agent: 0",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("doctor missing-agent output missing %q:\n%s", c, out)
		}
	}
}

func TestRunPolicyListActiveFormatting(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)

	runInit(nil)

	activeDir := filepath.Join(kit, "policies", "active")
	if err := os.WriteFile(filepath.Join(activeDir, "all-http-Request-news-yahoo-com.cedar"), []byte(`forbid(
  principal,
  action == Action::"http:Request",
  resource == Resource::"news.yahoo.com"
);`), 0o644); err != nil {
		t.Fatalf("write all-agent policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(activeDir, "hackerman-http-Request-news-google-com.cedar"), []byte(`permit(
  principal == Agent::"hackerman",
  action == Action::"http:Request",
  resource == Resource::"news.google.com"
);`), 0o644); err != nil {
		t.Fatalf("write agent policy: %v", err)
	}

	cap := startStdoutCapture(t)
	runPolicy([]string{"list"})
	out := cap.Stop()

	want := []string{
		"🟢 Active (2)",
		"Summary: 1 allow, 1 deny",
		"Scope: 1 all-agents, 1 agent-specific",
		"Files:",
		"[all|deny] all-http-Request-news-yahoo-com.cedar",
		"[agent|allow] hackerman-http-Request-news-google-com.cedar",
	}
	for _, fragment := range want {
		if !strings.Contains(out, fragment) {
			t.Fatalf("policy list output missing %q:\n%s", fragment, out)
		}
	}
}

func TestRunInboxFormatting(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)

	runInit(nil)

	logger, err := audit.NewLogger(filepath.Join(kit, "audit"))
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}
	if err := logger.Log(audit.Record{
		Agent:        "hackerman",
		Scope:        "hackerman",
		Action:       "http:Request",
		Resource:     "news.yahoo.com",
		Decision:     "deny",
		DecisionPath: "policy",
		DenialReason: "No policy permits hackerman to reach news.yahoo.com",
		Timestamp:    time.Date(2026, 3, 1, 11, 22, 33, 0, time.UTC),
	}); err != nil {
		t.Fatalf("log deny: %v", err)
	}

	cap := startStdoutCapture(t)
	runInbox(nil)
	out := cap.Stop()

	checks := []string{
		"📥 Pending review queue (1)",
		"🤖 hackerman  http:Request -> news.yahoo.com  [blocked since no policy exists]",
		"Approve with: loa approve <number>",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("inbox output missing %q:\n%s", c, out)
		}
	}
}

func TestRunInboxFormatting_MixedDenialsGolden(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)

	runInit(nil)

	logger, err := audit.NewLogger(filepath.Join(kit, "audit"))
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}
	if err := logger.Log(audit.Record{
		Agent:        "hackerman",
		Scope:        "hackerman",
		Action:       "http:Request",
		Resource:     "news.yahoo.com",
		Decision:     "deny",
		DecisionPath: "policy",
		DenialReason: "No policy permits hackerman to reach news.yahoo.com",
		Timestamp:    time.Date(2026, 3, 1, 11, 22, 33, 0, time.UTC),
	}); err != nil {
		t.Fatalf("log policy deny: %v", err)
	}
	if err := logger.Log(audit.Record{
		Agent:        "hackerman",
		Scope:        "hackerman",
		Action:       "exec:Run",
		Resource:     "source",
		Decision:     "permit",
		DecisionPath: "activity_unmapped",
		DenialReason: "unmapped command",
		Timestamp:    time.Date(2026, 3, 1, 11, 22, 34, 0, time.UTC),
	}); err != nil {
		t.Fatalf("log command activity: %v", err)
	}

	cap := startStdoutCapture(t)
	runInbox(nil)
	out := cap.Stop()

	wantFragments := []string{
		"📥 Pending review queue (1)",
		"http:Request -> news.yahoo.com  [blocked since no policy exists]",
		"Approve with: loa approve <number>",
	}
	for _, fragment := range wantFragments {
		if !strings.Contains(out, fragment) {
			t.Fatalf("inbox mixed output missing %q:\n%s", fragment, out)
		}
	}
	if strings.Contains(out, "reason: No policy permits") {
		t.Fatalf("no-policy reason should stay compact and not print reason line:\n%s", out)
	}
}

func TestDecisionPathLabel_ActivityPaths(t *testing.T) {
	if got := decisionPathLabel("activity_exec", "permit"); got != "activity observed" {
		t.Fatalf("decisionPathLabel(activity_exec)= %q, want activity observed", got)
	}
	if got := decisionPathLabel("shell_observe", "permit"); got != "activity observed" {
		t.Fatalf("decisionPathLabel(shell_observe)= %q, want activity observed", got)
	}
	if got := decisionPathLabel("activity_file", "permit"); got != "file activity observed" {
		t.Fatalf("decisionPathLabel(activity_file)= %q, want file activity observed", got)
	}
}

func TestPrintWatchEvents_FileActivitySummary(t *testing.T) {
	cap := startStderrCapture(t)
	printWatchEvents([]audit.Record{{
		Agent:        "hackerman",
		Action:       "file:UpdateSet",
		Resource:     "/workspace",
		Decision:     "permit",
		DecisionPath: "activity_file",
		Context: map[string]any{
			"files":       []string{"a.go", "b.go", "c.go", "d.go"},
			"total_files": 4,
		},
	}})
	out := cap.Stop()
	if !strings.Contains(out, "hackerman file:UpdateSet -> /workspace [file activity observed]") {
		t.Fatalf("missing file activity summary line:\n%s", out)
	}
	if !strings.Contains(out, "files: a.go, b.go, c.go, +1 more") {
		t.Fatalf("missing concise file list:\n%s", out)
	}
}

func TestCollectChangedFilesSince(t *testing.T) {
	root := t.TempDir()
	snap := filepath.Join(t.TempDir(), "snapshot")
	if err := os.WriteFile(filepath.Join(root, "old.txt"), []byte("old"), 0o644); err != nil {
		t.Fatalf("write old file: %v", err)
	}
	if err := os.WriteFile(snap, []byte("snap"), 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("new"), 0o644); err != nil {
		t.Fatalf("write new file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "ignored"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	files, total, err := collectChangedFilesSince(root, snap, 10)
	if err != nil {
		t.Fatalf("collectChangedFilesSince: %v", err)
	}
	if total != 1 {
		t.Fatalf("total changed files = %d, want 1 (files=%v)", total, files)
	}
	if len(files) != 1 || files[0] != "new.txt" {
		t.Fatalf("files = %v, want [new.txt]", files)
	}
}

func TestRunAuditSummary(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)
	runInit(nil)

	logger, err := audit.NewLogger(filepath.Join(kit, "audit"))
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}
	now := time.Now().UTC()
	records := []audit.Record{
		{
			Timestamp:    now.Add(-2 * time.Minute),
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "exec:Run",
			Resource:     "ls",
			Decision:     "permit",
			DecisionPath: "activity_exec",
		},
		{
			Timestamp:    now.Add(-90 * time.Second),
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "http:Request",
			Resource:     "news.google.com",
			Decision:     "permit",
			DecisionPath: "policy",
		},
		{
			Timestamp:    now.Add(-70 * time.Second),
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "file:UpdateSet",
			Resource:     "/workspace",
			Decision:     "permit",
			DecisionPath: "activity_file",
			Context: map[string]any{
				"total_files": 2,
				"files":       []string{"main.go", "README.md"},
			},
		},
	}
	for _, r := range records {
		if err := logger.Log(r); err != nil {
			t.Fatalf("log record: %v", err)
		}
	}

	cap := startStdoutCapture(t)
	runAudit([]string{"summary", "--agent", "hackerman", "--since", "10m"})
	out := cap.Stop()

	checks := []string{
		"Activity summary (hackerman, last 10m)",
		"Commands observed: 1",
		"Network requests: 1",
		"File update batches: 1",
		"Files updated (reported): 2",
		"Top hosts:",
		"news.google.com (1)",
		"Top files:",
		"main.go (1)",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("audit summary output missing %q:\n%s", c, out)
		}
	}
}

func TestRunPolicySuggest(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)
	runInit(nil)

	mgr := agent.NewManager(kit)
	if err := mgr.Create("hackerman", agent.CreateOpts{Runtime: "claude-code"}); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	logger, err := audit.NewLogger(filepath.Join(kit, "audit"))
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}
	now := time.Now().UTC()
	records := []audit.Record{
		{
			Timestamp:    now.Add(-2 * time.Hour),
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "http:Request",
			Resource:     "www.slackware.com",
			Decision:     "deny",
			DecisionPath: "policy",
			DenialReason: "No policy permits hackerman to reach www.slackware.com",
		},
		{
			Timestamp:    now.Add(-90 * time.Minute),
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "http:Request",
			Resource:     "www.slackware.com",
			Decision:     "deny",
			DecisionPath: "log",
			DenialReason: "No policy permits hackerman to reach www.slackware.com",
		},
		{
			Timestamp:    now.Add(-80 * time.Minute),
			Agent:        "hackerman",
			Scope:        "hackerman",
			Action:       "file:UpdateSet",
			Resource:     "/opt/app",
			Decision:     "permit",
			DecisionPath: "activity_file",
			Context: map[string]any{
				"total_files": 2,
				"files":       []string{"main.go", "go.mod"},
			},
		},
	}
	for _, r := range records {
		if err := logger.Log(r); err != nil {
			t.Fatalf("log record: %v", err)
		}
	}

	cap := startStdoutCapture(t)
	runPolicy([]string{"suggest", "--agent", "hackerman", "--since", "240h", "--interactive=false"})
	out := cap.Stop()

	checks := []string{
		"Suggestions for hackerman",
		"Network suggestions: 1",
		"www.slackware.com",
		"broader option: *.slackware.com",
		"Filesystem suggestions: 1",
		"RW /opt/app",
		"observed: 2 events",
		"Tip: rerun with --interactive to activate network suggestions.",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Fatalf("policy suggest output missing %q:\n%s", c, out)
		}
	}
}

func TestRunInitCreatesPrincipalsMapping(t *testing.T) {
	kit := t.TempDir()
	t.Setenv("LOA_KIT", kit)

	runInit(nil)

	path := filepath.Join(kit, "config", "principals.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read principals.yml: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "principals:") {
		t.Fatalf("principals.yml missing principals key:\n%s", text)
	}
	if !strings.Contains(text, "allow_agents:") || !strings.Contains(text, "- \"*\"") {
		t.Fatalf("principals.yml missing wildcard allow list:\n%s", text)
	}
}
