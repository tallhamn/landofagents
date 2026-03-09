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

// StagePolicy writes a proposal's Cedar to policies/staged.
// Returns the staged path.
func (p *Pipeline) StagePolicy(proposal ProposalWithCedar) (string, error) {
	stagedDir := filepath.Join(p.cfg.KitDir, "policies", "staged")
	if err := os.MkdirAll(stagedDir, 0755); err != nil {
		return "", fmt.Errorf("create staged policies dir: %w", err)
	}

	filename := sanitizePolicyFilename(proposal.Filename)
	path := filepath.Join(stagedDir, filename)
	if err := os.WriteFile(path, []byte(proposal.Cedar), 0644); err != nil {
		return "", fmt.Errorf("write staged policy: %w", err)
	}
	if err := p.logLifecycleEvent(proposal.Agent, "policy:Stage", filename, map[string]any{
		"state": "staged",
		"path":  path,
	}); err != nil {
		return "", fmt.Errorf("audit stage event: %w", err)
	}
	return path, nil
}

// ActivatePolicy promotes a staged policy to policies/active and removes it from staged.
// Returns the active path.
func (p *Pipeline) ActivatePolicy(stagedPath string) (string, error) {
	filename := sanitizePolicyFilename(filepath.Base(stagedPath))
	activeDir := filepath.Join(p.cfg.KitDir, "policies", "active")
	if err := os.MkdirAll(activeDir, 0755); err != nil {
		return "", fmt.Errorf("create active policies dir: %w", err)
	}

	data, err := os.ReadFile(stagedPath)
	if err != nil {
		return "", fmt.Errorf("read staged policy: %w", err)
	}

	activePath := filepath.Join(activeDir, filename)
	if err := os.WriteFile(activePath, data, 0644); err != nil {
		return "", fmt.Errorf("write active policy: %w", err)
	}
	if err := os.Remove(stagedPath); err != nil {
		return "", fmt.Errorf("remove staged policy: %w", err)
	}
	if err := p.logLifecycleEvent("", "policy:Activate", filename, map[string]any{
		"state":      "active",
		"from_stage": stagedPath,
		"to_active":  activePath,
	}); err != nil {
		return "", fmt.Errorf("audit activate event: %w", err)
	}
	return activePath, nil
}

// ActivateStagedByName promotes a single staged policy by filename.
func (p *Pipeline) ActivateStagedByName(filename string) (string, error) {
	filename = sanitizePolicyFilename(filename)
	stagedPath := filepath.Join(p.cfg.KitDir, "policies", "staged", filename)
	if _, err := os.Stat(stagedPath); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("staged policy not found: %s", filename)
		}
		return "", fmt.Errorf("stat staged policy: %w", err)
	}
	return p.ActivatePolicy(stagedPath)
}

// ActivateAllStaged promotes all staged policies in deterministic name order.
func (p *Pipeline) ActivateAllStaged() ([]string, error) {
	staged, err := p.ListStagedPolicies()
	if err != nil {
		return nil, err
	}
	if len(staged) == 0 {
		return nil, nil
	}

	var activated []string
	for _, filename := range staged {
		path, err := p.ActivateStagedByName(filename)
		if err != nil {
			return activated, err
		}
		activated = append(activated, path)
	}
	return activated, nil
}

// ListStagedPolicies lists policy filenames in policies/staged.
func (p *Pipeline) ListStagedPolicies() ([]string, error) {
	return listPolicyFiles(filepath.Join(p.cfg.KitDir, "policies", "staged"))
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
