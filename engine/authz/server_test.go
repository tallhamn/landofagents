package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marcusmom/land-of-agents/engine/audit"
	"github.com/marcusmom/land-of-agents/engine/netscope"
	"github.com/marcusmom/land-of-agents/engine/oneshot"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "kit")
}

func TestAllowKnownDomain(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "", logger, ModeEnforce)
	handler := srv.Handler()

	// api.wrike.com is permitted by testdata/kit/policies/active/permit-wrike.cedar
	req := httptest.NewRequest("GET", "http://api.wrike.com/tasks", nil)
	req.Host = "api.wrike.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Check audit log
	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Decision != "permit" {
		t.Errorf("decision: got %q, want permit", records[0].Decision)
	}
	if records[0].Resource != "api.wrike.com" {
		t.Errorf("resource: got %q", records[0].Resource)
	}
}

func TestAuditContextIncludesRunIDWhenConfigured(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "run-123", logger, ModeEnforce)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
	req.Host = "evil.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("expected at least one audit record")
	}
	if records[0].Context == nil || records[0].Context["run_id"] != "run-123" {
		t.Fatalf("expected run_id in context, got %+v", records[0].Context)
	}
}

func TestDenyUnknownDomain(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "", logger, ModeEnforce)
	handler := srv.Handler()

	// evil.com has no permit policy
	req := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
	req.Host = "evil.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	// Check response body
	var resp denyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal deny response: %v", err)
	}
	if !resp.LOADenial {
		t.Error("expected loa_denial to be true")
	}
	if resp.Resource != "evil.com" {
		t.Errorf("resource: got %q", resp.Resource)
	}

	// Check audit log
	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Decision != "deny" {
		t.Errorf("decision: got %q, want deny", records[0].Decision)
	}
}

func TestDenyMissingHostMetadata(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "", logger, ModeEnforce)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "http://placeholder.local/path", nil)
	req.Host = ""
	req.Header.Del("Host")
	req.Header.Del("X-Forwarded-Host")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var resp denyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal deny response: %v", err)
	}
	if resp.Reason != "missing destination host metadata" {
		t.Fatalf("unexpected denial reason: %q", resp.Reason)
	}
}

func TestDenyDifferentAgent(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	// carmack has no policy for wrike.com (only goggins does via group membership + permit-wrike.cedar)
	// Actually, permit-wrike.cedar permits AgentGroup::"agent" which includes both.
	// Let's test with a domain that has no policy at all.
	srv := NewServer(testdataDir(), "carmack", "", logger, ModeEnforce)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "http://news.google.com/", nil)
	req.Host = "news.google.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	records, _ := logger.ReadAll()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Agent != "carmack" {
		t.Errorf("agent: got %q", records[0].Agent)
	}
}

func TestHTTPSConnectHostStripping(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "", logger, ModeEnforce)
	handler := srv.Handler()

	// HTTPS CONNECT sends Host as "domain:443"
	req := httptest.NewRequest("CONNECT", "http://api.wrike.com:443", nil)
	req.Host = "api.wrike.com:443"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for wrike.com:443, got %d: %s", w.Code, w.Body.String())
	}

	records, _ := logger.ReadAll()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Resource != "api.wrike.com" {
		t.Errorf("resource should strip port: got %q", records[0].Resource)
	}
}

func TestHealthz(t *testing.T) {
	srv := NewServer(testdataDir(), "goggins", "", nil, ModeEnforce)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("healthz: expected 200, got %d", w.Code)
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"api.wrike.com", "api.wrike.com"},
		{"api.wrike.com:443", "api.wrike.com"},
		{"News.Google.Com:80", "news.google.com"},
		{"localhost:8080", "localhost"},
		{"", ""},
		{"  api.wrike.com  ", "api.wrike.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractDomain(tt.input)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestObserveModePermitsAll(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "", logger, ModeLog)
	handler := srv.Handler()

	// evil.com has no permit policy — log mode should still return 200
	req := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
	req.Host = "evil.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("log mode: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("x-loa-decision") != "log" {
		t.Errorf("expected x-loa-decision=observe, got %q", w.Header().Get("x-loa-decision"))
	}

	// Audit should show the denial was logged
	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Decision != "deny" {
		t.Errorf("decision: got %q, want deny", records[0].Decision)
	}
	if records[0].DecisionPath != "log" {
		t.Errorf("decision_path: got %q, want observe", records[0].DecisionPath)
	}
}

func TestObserveMode(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "", logger, ModeLog)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
	req.Host = "evil.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("log mode: expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("x-loa-decision"); got != "log" {
		t.Fatalf("log mode should emit observe decision, got %q", got)
	}
}

func TestApproveModeTimesOut(t *testing.T) {
	auditDir := t.TempDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(testdataDir(), "goggins", "", logger, ModeAsk)
	srv.ApproveTimeout = 100 * time.Millisecond // short timeout for test
	handler := srv.Handler()

	// evil.com has no permit policy — ask mode should hold then return 403
	req := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
	req.Host = "evil.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ask mode timeout: expected 403, got %d", w.Code)
	}

	var resp denyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.LOADenial {
		t.Error("expected loa_denial to be true")
	}

	// Verify denial was logged
	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) < 1 {
		t.Fatal("expected at least 1 audit record for denial")
	}
	if records[0].Decision != "deny" {
		t.Errorf("first record decision: got %q, want deny", records[0].Decision)
	}
}

func TestApproveModeWaitsForPermission(t *testing.T) {
	// Copy testdata kit to a temp directory so we can write to it
	tmpKit := t.TempDir()
	copyTestKit(t, testdataDir(), tmpKit)

	auditDir := filepath.Join(tmpKit, "audit")
	os.MkdirAll(auditDir, 0755)
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(tmpKit, "goggins", "", logger, ModeAsk)
	srv.ApproveTimeout = 5 * time.Second
	handler := srv.Handler()

	// Fire request in goroutine — it will block until permission appears
	type result struct {
		code int
	}
	resultCh := make(chan result, 1)
	go func() {
		req := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
		req.Host = "evil.com"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		resultCh <- result{code: w.Code}
	}()

	// Wait a bit, then write a permit policy to the active policy set.
	time.Sleep(300 * time.Millisecond)
	permDir := filepath.Join(tmpKit, "policies", "active")
	os.MkdirAll(permDir, 0755)
	policy := `permit(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"evil.com"
);
`
	if err := os.WriteFile(filepath.Join(permDir, "permit-evil.cedar"), []byte(policy), 0644); err != nil {
		t.Fatalf("write permit policy: %v", err)
	}

	// Wait for the request to complete
	select {
	case res := <-resultCh:
		if res.code != http.StatusOK {
			t.Errorf("expected 200 after approval, got %d", res.code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request did not complete within 10s")
	}
}

func TestOneTimeAllowBypassesPolicyOnce(t *testing.T) {
	tmpKit := t.TempDir()
	copyTestKit(t, testdataDir(), tmpKit)

	auditDir := filepath.Join(tmpKit, "audit")
	os.MkdirAll(auditDir, 0755)
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if _, err := oneshot.Add(tmpKit, oneshot.Decision{
		Agent:    "goggins",
		Action:   "http:Request",
		Resource: "evil.com",
		Effect:   oneshot.EffectAllow,
	}); err != nil {
		t.Fatalf("oneshot.Add: %v", err)
	}

	srv := NewServer(tmpKit, "goggins", "", logger, ModeEnforce)
	handler := srv.Handler()

	req1 := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
	req1.Host = "evil.com"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request expected 200 from one-time allow, got %d", w1.Code)
	}

	req2 := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
	req2.Host = "evil.com"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("second request expected 403 after one-time consume, got %d", w2.Code)
	}

	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}
	if records[0].DecisionPath != "one_time_allow" {
		t.Fatalf("first decision path = %q, want one_time_allow", records[0].DecisionPath)
	}
}

func TestOneTimeDenyUnblocksGateWait(t *testing.T) {
	tmpKit := t.TempDir()
	copyTestKit(t, testdataDir(), tmpKit)

	auditDir := filepath.Join(tmpKit, "audit")
	os.MkdirAll(auditDir, 0755)
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(tmpKit, "goggins", "", logger, ModeAsk)
	srv.ApproveTimeout = 5 * time.Second
	handler := srv.Handler()

	type result struct {
		code int
		body string
	}
	resultCh := make(chan result, 1)
	go func() {
		req := httptest.NewRequest("GET", "http://evil.com/exfil", nil)
		req.Host = "evil.com"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		resultCh <- result{code: w.Code, body: w.Body.String()}
	}()

	time.Sleep(250 * time.Millisecond)
	if _, err := oneshot.Add(tmpKit, oneshot.Decision{
		Agent:    "goggins",
		Action:   "http:Request",
		Resource: "evil.com",
		Effect:   oneshot.EffectDeny,
	}); err != nil {
		t.Fatalf("oneshot.Add: %v", err)
	}

	select {
	case res := <-resultCh:
		if res.code != http.StatusForbidden {
			t.Fatalf("expected 403 from one-time deny, got %d", res.code)
		}
		if !strings.Contains(strings.ToLower(res.body), "blocked once") {
			t.Fatalf("expected one-time deny reason in body, got %q", res.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request should have been denied quickly by one-time decision")
	}

	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	found := false
	for _, r := range records {
		if r.DecisionPath == "one_time_deny" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected one_time_deny record, got %+v", records)
	}
}

func TestAllowViaRegistrableDomainPolicy(t *testing.T) {
	tmpKit := t.TempDir()
	copyTestKit(t, testdataDir(), tmpKit)

	permDir := filepath.Join(tmpKit, "policies", "active")
	os.MkdirAll(permDir, 0755)
	policy := `permit(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"google.com"
);
`
	if err := os.WriteFile(filepath.Join(permDir, "permit-google-root.cedar"), []byte(policy), 0644); err != nil {
		t.Fatalf("write permit policy: %v", err)
	}

	auditDir := filepath.Join(tmpKit, "audit")
	os.MkdirAll(auditDir, 0755)
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(tmpKit, "goggins", "", logger, ModeEnforce)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "http://news.google.com/rss", nil)
	req.Host = "news.google.com"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) != 1 || records[0].Decision != "permit" {
		t.Fatalf("expected one permit record, got %+v", records)
	}
	if records[0].Resource != "news.google.com" {
		t.Fatalf("expected resource to remain requested host, got %q", records[0].Resource)
	}
}

func TestApproveModeWaitsForRegistrableDomainPolicy(t *testing.T) {
	tmpKit := t.TempDir()
	copyTestKit(t, testdataDir(), tmpKit)

	auditDir := filepath.Join(tmpKit, "audit")
	os.MkdirAll(auditDir, 0755)
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(tmpKit, "goggins", "", logger, ModeAsk)
	srv.ApproveTimeout = 5 * time.Second
	handler := srv.Handler()

	type result struct {
		code int
	}
	resultCh := make(chan result, 1)
	go func() {
		req := httptest.NewRequest("GET", "http://news.google.com/rss", nil)
		req.Host = "news.google.com"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		resultCh <- result{code: w.Code}
	}()

	time.Sleep(300 * time.Millisecond)
	permDir := filepath.Join(tmpKit, "policies", "active")
	os.MkdirAll(permDir, 0755)
	policy := `permit(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"google.com"
);
`
	if err := os.WriteFile(filepath.Join(permDir, "permit-google-root.cedar"), []byte(policy), 0644); err != nil {
		t.Fatalf("write permit policy: %v", err)
	}

	select {
	case res := <-resultCh:
		if res.code != http.StatusOK {
			t.Fatalf("expected 200 after domain approval, got %d", res.code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request did not complete within 10s")
	}
}

func TestRegistrableDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{host: "news.google.com", want: "google.com"},
		{host: "api.anthropic.com", want: "anthropic.com"},
		{host: "raw.githubusercontent.com", want: "githubusercontent.com"},
		{host: "www.dn.se", want: "dn.se"},
		{host: "localhost", want: "localhost"},
		{host: "", want: ""},
	}
	for _, tt := range tests {
		if got := netscope.EffectiveDomain(tt.host); got != tt.want {
			t.Fatalf("EffectiveDomain(%q)=%q want %q", tt.host, got, tt.want)
		}
	}
}

func TestAllowViaRegistrableDomainPolicy_DNSE(t *testing.T) {
	tmpKit := t.TempDir()
	copyTestKit(t, testdataDir(), tmpKit)

	permDir := filepath.Join(tmpKit, "policies", "active")
	os.MkdirAll(permDir, 0755)
	policy := `permit(
  principal == Agent::"goggins",
  action == Action::"http:Request",
  resource == Resource::"dn.se"
);
`
	if err := os.WriteFile(filepath.Join(permDir, "permit-dn-root.cedar"), []byte(policy), 0644); err != nil {
		t.Fatalf("write permit policy: %v", err)
	}

	auditDir := filepath.Join(tmpKit, "audit")
	os.MkdirAll(auditDir, 0755)
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := NewServer(tmpKit, "goggins", "", logger, ModeEnforce)
	handler := srv.Handler()

	req := httptest.NewRequest("GET", "http://www.dn.se/", nil)
	req.Host = "www.dn.se"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func copyTestKit(t *testing.T, src, dst string) {
	t.Helper()
	for _, subdir := range []string{"config", "policies", filepath.Join("policies", "active")} {
		srcDir := filepath.Join(src, subdir)
		dstDir := filepath.Join(dst, subdir)
		os.MkdirAll(dstDir, 0755)
		entries, err := os.ReadDir(srcDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
			if err != nil {
				t.Fatalf("copy %s: %v", e.Name(), err)
			}
			if err := os.WriteFile(filepath.Join(dstDir, e.Name()), data, 0644); err != nil {
				t.Fatalf("write %s: %v", e.Name(), err)
			}
		}
	}
}
