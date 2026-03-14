package approval

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcusmom/land-of-agents/engine/audit"
)

func TestProcessFallback(t *testing.T) {
	// No API key — should produce template Cedar
	kitDir := testKitDir(t)
	p := NewPipeline(PipelineConfig{
		KitDir: kitDir,
	})

	denials := []audit.Record{
		{
			ID:       "AUD-000001",
			Agent:    "goggins",
			Action:   "http:Request",
			Resource: "api.wrike.com",
			Decision: "deny",
		},
	}

	result, err := p.Process(context.Background(), denials)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(result.Proposals) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(result.Proposals))
	}

	prop := result.Proposals[0]
	if prop.Agent != "goggins" {
		t.Errorf("agent: got %q", prop.Agent)
	}
	if !strings.Contains(prop.Cedar, `Agent::"goggins"`) {
		t.Errorf("Cedar should contain agent: %s", prop.Cedar)
	}
	if !strings.Contains(prop.Cedar, `Resource::"api.wrike.com"`) {
		t.Errorf("Cedar should contain resource: %s", prop.Cedar)
	}
	if !strings.Contains(prop.Description, "goggins") {
		t.Errorf("description should mention agent: %s", prop.Description)
	}
	if prop.Filename == "" {
		t.Error("filename should not be empty")
	}
}

func TestWriteActivePolicy(t *testing.T) {
	kitDir := t.TempDir()
	p := NewPipeline(PipelineConfig{KitDir: kitDir})

	proposal := ProposalWithCedar{
		Agent:    "goggins",
		Cedar:    "permit(\n  principal == Agent::\"goggins\",\n  action == Action::\"http:Request\",\n  resource == Resource::\"api.wrike.com\"\n);\n",
		Filename: "goggins-http-wrike.cedar",
	}

	activePath, err := p.WriteActivePolicy(proposal)
	if err != nil {
		t.Fatalf("WriteActivePolicy: %v", err)
	}

	if !strings.Contains(activePath, filepath.Join("policies", "active")) {
		t.Errorf("expected path under policies/active, got: %s", activePath)
	}
	if !strings.HasSuffix(activePath, "goggins-http-wrike.cedar") {
		t.Errorf("unexpected path: %s", activePath)
	}

	data, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(data) != proposal.Cedar {
		t.Errorf("file content mismatch:\ngot:  %s\nwant: %s", data, proposal.Cedar)
	}

	// Verify lifecycle audit record
	logger, err := audit.NewLogger(filepath.Join(kitDir, "audit"))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) < 1 {
		t.Fatalf("expected lifecycle audit record, got %d", len(records))
	}

	var sawApprove bool
	for _, r := range records {
		if r.DecisionPath == "lifecycle" && r.Action == "policy:Approve" && r.PolicyRef == "goggins-http-wrike.cedar" {
			sawApprove = true
		}
	}
	if !sawApprove {
		t.Fatal("missing policy:Approve lifecycle audit record")
	}
}

func TestProcessEmpty(t *testing.T) {
	p := NewPipeline(PipelineConfig{KitDir: t.TempDir()})
	result, err := p.Process(context.Background(), nil)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(result.Proposals) != 0 {
		t.Errorf("expected 0 proposals, got %d", len(result.Proposals))
	}
}

func TestTemplateCedar(t *testing.T) {
	d := audit.Record{Agent: "carmack", Action: "http:Request", Resource: "github.com"}
	cedar := templateCedar(d)
	if !strings.Contains(cedar, `Agent::"carmack"`) {
		t.Errorf("missing agent in Cedar: %s", cedar)
	}
	if !strings.Contains(cedar, `Action::"http:Request"`) {
		t.Errorf("missing action in Cedar: %s", cedar)
	}
	if !strings.Contains(cedar, `Resource::"github.com"`) {
		t.Errorf("missing resource in Cedar: %s", cedar)
	}
	if !strings.HasPrefix(cedar, "permit(") {
		t.Errorf("should start with permit: %s", cedar)
	}
}

func TestTemplateFilename(t *testing.T) {
	d := audit.Record{Agent: "goggins", Action: "http:Request", Resource: "api.wrike.com"}
	filename := templateFilename(d)
	if !strings.HasSuffix(filename, ".cedar") {
		t.Errorf("should end with .cedar: %s", filename)
	}
	if strings.ContainsAny(filename, ":/") {
		t.Errorf("filename should not contain : or /: %s", filename)
	}
}

// testKitDir returns the testdata/kit path.
func testKitDir(t *testing.T) string {
	t.Helper()
	// The testdata dir is at the repo root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Walk up to find testdata/kit
	dir := wd
	for {
		candidate := filepath.Join(dir, "testdata", "kit")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find testdata/kit")
		}
		dir = parent
	}
}
