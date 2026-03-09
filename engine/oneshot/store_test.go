package oneshot

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAddAndConsumeMatch(t *testing.T) {
	kit := t.TempDir()
	_, err := Add(kit, Decision{
		Agent:    "hackerman",
		Action:   "http:Request",
		Resource: "registry.npmjs.org",
		Effect:   EffectAllow,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	d, ok, err := ConsumeMatch(kit, "hackerman", "http:Request", "registry.npmjs.org", "")
	if err != nil {
		t.Fatalf("ConsumeMatch: %v", err)
	}
	if !ok {
		t.Fatal("expected match")
	}
	if d.Effect != EffectAllow {
		t.Fatalf("effect=%q want %q", d.Effect, EffectAllow)
	}

	_, ok, err = ConsumeMatch(kit, "hackerman", "http:Request", "registry.npmjs.org", "")
	if err != nil {
		t.Fatalf("ConsumeMatch second: %v", err)
	}
	if ok {
		t.Fatal("expected oneshot to be consumed once")
	}

	used, err := filepath.Glob(filepath.Join(kit, "audit", "oneshot", "consumed", "*.used"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(used) == 0 {
		t.Fatal("expected consumed marker file")
	}
}

func TestConsumeMatch_Expired(t *testing.T) {
	kit := t.TempDir()
	_, err := Add(kit, Decision{
		Agent:     "hackerman",
		Action:    "http:Request",
		Resource:  "news.yahoo.com",
		Effect:    EffectDeny,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	_, ok, err := ConsumeMatch(kit, "hackerman", "http:Request", "news.yahoo.com", "")
	if err != nil {
		t.Fatalf("ConsumeMatch: %v", err)
	}
	if ok {
		t.Fatal("did not expect expired decision to match")
	}
}

func TestConsumeMatch_WildcardResource(t *testing.T) {
	kit := t.TempDir()
	_, err := Add(kit, Decision{
		Agent:    "*",
		Action:   "http:Request",
		Resource: "*.npmjs.org",
		Effect:   EffectAllow,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, ok, err := ConsumeMatch(kit, "hackerman", "http:Request", "registry.npmjs.org", ""); err != nil || !ok {
		t.Fatalf("expected wildcard match, ok=%v err=%v", ok, err)
	}
}

func TestConsumeMatch_RunIDScope(t *testing.T) {
	kit := t.TempDir()
	_, err := Add(kit, Decision{
		Agent:    "hackerman",
		Action:   "http:Request",
		Resource: "news.ycombinator.com",
		RunID:    "run-123",
		Effect:   EffectAllow,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	if _, ok, err := ConsumeMatch(kit, "hackerman", "http:Request", "news.ycombinator.com", "run-999"); err != nil {
		t.Fatalf("ConsumeMatch mismatch run: %v", err)
	} else if ok {
		t.Fatal("expected no match for non-matching run id")
	}

	if _, ok, err := ConsumeMatch(kit, "hackerman", "http:Request", "news.ycombinator.com", "run-123"); err != nil {
		t.Fatalf("ConsumeMatch matching run: %v", err)
	} else if !ok {
		t.Fatal("expected run-scoped match")
	}
}
