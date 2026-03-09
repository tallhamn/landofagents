package oneshot

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Decision struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	RunID     string    `json:"run_id,omitempty"`
	Effect    Effect    `json:"effect"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func pendingDir(kitDir string) string {
	return filepath.Join(kitDir, "audit", "oneshot", "pending")
}

func consumedDir(kitDir string) string {
	return filepath.Join(kitDir, "audit", "oneshot", "consumed")
}

// Add queues a one-time allow/deny decision that will be consumed on first match.
func Add(kitDir string, d Decision) (string, error) {
	d.Agent = strings.ToLower(strings.TrimSpace(d.Agent))
	d.Action = strings.TrimSpace(d.Action)
	d.Resource = strings.ToLower(strings.TrimSpace(d.Resource))
	d.RunID = strings.TrimSpace(d.RunID)
	if d.Agent == "" || d.Action == "" || d.Resource == "" {
		return "", fmt.Errorf("oneshot decision requires agent, action, and resource")
	}
	if d.Effect != EffectAllow && d.Effect != EffectDeny {
		return "", fmt.Errorf("oneshot decision effect must be allow or deny")
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	if d.ExpiresAt.IsZero() {
		d.ExpiresAt = d.CreatedAt.Add(10 * time.Minute)
	}
	if d.ID == "" {
		d.ID = fmt.Sprintf("%d-%s", d.CreatedAt.UnixNano(), randomHex(4))
	}

	dir := pendingDir(kitDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	dst := filepath.Join(dir, d.ID+".json")
	tmp := dst + ".tmp"
	body, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(tmp, body, 0644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dst, nil
}

// ConsumeMatch finds and consumes the first pending one-time decision that matches.
func ConsumeMatch(kitDir, agent, action, resource, runID string) (Decision, bool, error) {
	agent = strings.ToLower(strings.TrimSpace(agent))
	action = strings.TrimSpace(action)
	resource = strings.ToLower(strings.TrimSpace(resource))
	runID = strings.TrimSpace(runID)

	dir := pendingDir(kitDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Decision{}, false, nil
		}
		return Decision{}, false, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	consumed := consumedDir(kitDir)
	_ = os.MkdirAll(consumed, 0755)

	now := time.Now().UTC()
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var d Decision
		if err := json.Unmarshal(body, &d); err != nil {
			continue
		}
		if !d.ExpiresAt.IsZero() && now.After(d.ExpiresAt) {
			_ = os.Remove(path)
			continue
		}
		if !matches(d, agent, action, resource, runID) {
			continue
		}
		dst := filepath.Join(consumed, e.Name()+".used")
		if err := os.Rename(path, dst); err != nil {
			continue
		}
		return d, true, nil
	}
	return Decision{}, false, nil
}

func matches(d Decision, agent, action, resource, runID string) bool {
	da := strings.ToLower(strings.TrimSpace(d.Agent))
	if da != "*" && da != agent {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(d.Action), action) {
		return false
	}
	drun := strings.TrimSpace(d.RunID)
	if drun != "" && drun != "*" && drun != runID {
		return false
	}
	dr := strings.ToLower(strings.TrimSpace(d.Resource))
	if dr == resource {
		return true
	}
	if strings.HasPrefix(dr, "*.") {
		base := strings.TrimPrefix(dr, "*.")
		return resource == base || strings.HasSuffix(resource, "."+base)
	}
	return false
}

func randomHex(n int) string {
	if n <= 0 {
		return "0"
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0"
	}
	return hex.EncodeToString(b)
}
