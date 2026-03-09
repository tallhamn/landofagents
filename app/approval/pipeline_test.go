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

func TestStageAndActivatePolicy(t *testing.T) {
	kitDir := t.TempDir()
	p := NewPipeline(PipelineConfig{KitDir: kitDir})

	proposal := ProposalWithCedar{
		Agent:    "goggins",
		Cedar:    "permit(\n  principal == Agent::\"goggins\",\n  action == Action::\"http:Request\",\n  resource == Resource::\"api.wrike.com\"\n);\n",
		Filename: "goggins-http-wrike.cedar",
	}

	stagedPath, err := p.StagePolicy(proposal)
	if err != nil {
		t.Fatalf("StagePolicy: %v", err)
	}

	if !strings.Contains(stagedPath, filepath.Join("policies", "staged")) {
		t.Errorf("expected staged path under policies/staged, got: %s", stagedPath)
	}
	if !strings.HasSuffix(stagedPath, "goggins-http-wrike.cedar") {
		t.Errorf("unexpected staged path: %s", stagedPath)
	}

	data, err := os.ReadFile(stagedPath)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(data) != proposal.Cedar {
		t.Errorf("file content mismatch:\ngot:  %s\nwant: %s", data, proposal.Cedar)
	}

	// Verify policies/staged directory was created
	stagedDir := filepath.Join(kitDir, "policies", "staged")
	info, err := os.Stat(stagedDir)
	if err != nil {
		t.Fatalf("staged dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("staged should be a directory")
	}

	activePath, err := p.ActivatePolicy(stagedPath)
	if err != nil {
		t.Fatalf("ActivatePolicy: %v", err)
	}
	if !strings.Contains(activePath, filepath.Join("policies", "active")) {
		t.Errorf("expected active path under policies/active, got: %s", activePath)
	}
	if _, err := os.Stat(stagedPath); err == nil {
		t.Errorf("staged policy should be removed after activation: %s", stagedPath)
	}
	activeData, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read active policy: %v", err)
	}
	if string(activeData) != proposal.Cedar {
		t.Errorf("active file content mismatch:\ngot:  %s\nwant: %s", activeData, proposal.Cedar)
	}

	logger, err := audit.NewLogger(filepath.Join(kitDir, "audit"))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	records, err := logger.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(records) < 2 {
		t.Fatalf("expected lifecycle audit records, got %d", len(records))
	}

	var sawStage, sawActivate bool
	for _, r := range records {
		if r.DecisionPath != "lifecycle" {
			continue
		}
		if r.Action == "policy:Stage" && r.PolicyRef == "goggins-http-wrike.cedar" {
			sawStage = true
		}
		if r.Action == "policy:Activate" && r.PolicyRef == "goggins-http-wrike.cedar" {
			sawActivate = true
		}
	}
	if !sawStage {
		t.Fatal("missing policy:Stage lifecycle audit record")
	}
	if !sawActivate {
		t.Fatal("missing policy:Activate lifecycle audit record")
	}
}

func TestActivateAllStaged(t *testing.T) {
	kitDir := t.TempDir()
	p := NewPipeline(PipelineConfig{KitDir: kitDir})

	for _, name := range []string{"b.cedar", "a.cedar"} {
		_, err := p.StagePolicy(ProposalWithCedar{
			Agent:    "goggins",
			Filename: name,
			Cedar:    "permit(principal, action, resource);",
		})
		if err != nil {
			t.Fatalf("StagePolicy(%s): %v", name, err)
		}
	}

	activated, err := p.ActivateAllStaged()
	if err != nil {
		t.Fatalf("ActivateAllStaged: %v", err)
	}
	if len(activated) != 2 {
		t.Fatalf("expected 2 activated policies, got %d", len(activated))
	}

	staged, err := p.ListStagedPolicies()
	if err != nil {
		t.Fatalf("ListStagedPolicies: %v", err)
	}
	if len(staged) != 0 {
		t.Fatalf("expected no staged policies after activation, got %v", staged)
	}

	active, err := p.ListActivePolicies()
	if err != nil {
		t.Fatalf("ListActivePolicies: %v", err)
	}
	if len(active) != 2 || active[0] != "a.cedar" || active[1] != "b.cedar" {
		t.Fatalf("unexpected active list: %v", active)
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
