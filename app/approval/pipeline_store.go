package approval

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	gaptrail "github.com/marcusmom/land-of-agents/gap/trail"
	"github.com/marcusmom/land-of-agents/engine/services/loaledger"
)

// WriteActivePolicy writes a proposal's Cedar directly to policies/active.
// If a policy with the same filename already exists, it is replaced and the
// overwrite is recorded in the lifecycle audit event.
// Returns the active path.
func (p *Pipeline) WriteActivePolicy(proposal ProposalWithCedar) (string, error) {
	activeDir := filepath.Join(p.cfg.KitDir, "policies", "active")
	if err := os.MkdirAll(activeDir, 0750); err != nil {
		return "", fmt.Errorf("create active policies dir: %w", err)
	}

	filename := sanitizePolicyFilename(proposal.Filename)
	path := filepath.Join(activeDir, filename)

	// Detect and record overwrites so the audit trail captures replacements.
	var overwrote bool
	if _, err := os.Stat(path); err == nil {
		overwrote = true
	}

	if err := os.WriteFile(path, []byte(proposal.Cedar), 0640); err != nil {
		return "", fmt.Errorf("write active policy: %w", err)
	}
	ctx := map[string]any{
		"state": "active",
		"path":  path,
	}
	if overwrote {
		ctx["overwrote_existing"] = true
	}
	if err := p.logLifecycleEvent(proposal.Agent, "policy:Approve", filename, ctx); err != nil {
		return "", fmt.Errorf("audit approve event: %w", err)
	}
	return path, nil
}

// ListActivePolicies lists policy filenames in policies/active.
func (p *Pipeline) ListActivePolicies() ([]string, error) {
	return listPolicyFiles(filepath.Join(p.cfg.KitDir, "policies", "active"))
}

func listPolicyFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read policy dir %s: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".cedar" {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)
	return files, nil
}

func sanitizePolicyFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." {
		return "policy.cedar"
	}
	if filepath.Ext(name) != ".cedar" {
		name += ".cedar"
	}
	return name
}

func (p *Pipeline) logLifecycleEvent(agentName, action, policyRef string, ctx map[string]any) error {
	ledger, err := loaledger.New(p.cfg.KitDir)
	if err != nil {
		return err
	}

	agent := strings.TrimSpace(agentName)
	if agent == "" {
		agent = "system"
	}

	return ledger.AppendEvent(gaptrail.Event{
		Version:      gaptrail.VersionV1,
		EventID:      fmt.Sprintf("AUD-POL-%d", time.Now().UnixNano()),
		EventType:    "policy.activation",
		AgentID:      agent,
		Scope:        agent,
		Action:       action,
		Resource:     policyRef,
		Decision:     "permit",
		DecisionPath: "lifecycle",
		PolicyRef:    policyRef,
		Context:      ctx,
	})
}
