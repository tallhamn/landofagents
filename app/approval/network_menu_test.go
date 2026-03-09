package approval

import "testing"

func TestBuildNetworkDecisionMenu_Domain(t *testing.T) {
	menu := buildNetworkDecisionMenu("hackerman", "registry.npmjs.org", "*.npmjs.org", false)
	if menu.HostOnly {
		t.Fatal("expected non-host-only menu")
	}
	if len(menu.Options) != 10 {
		t.Fatalf("options len=%d want 10", len(menu.Options))
	}
	if menu.maxIndex() != 9 {
		t.Fatalf("maxIndex=%d want 9", menu.maxIndex())
	}
	got, ok := menu.selectByInput("0")
	if !ok {
		t.Fatal("expected option 0 to exist")
	}
	if got.Decision != Approved || got.Scope != AllAgents || got.NetworkScope != NetworkScopeDomain || got.Effect != PolicyPermit {
		t.Fatalf("option 0 mismatch: %+v", got)
	}
	got, ok = menu.selectByInput("9")
	if !ok {
		t.Fatal("expected option 9 to exist")
	}
	if got.Decision != Approved || got.Scope != AllAgents || got.NetworkScope != NetworkScopeDomain || got.Effect != PolicyForbid {
		t.Fatalf("option 9 mismatch: %+v", got)
	}
	if _, ok := menu.selectByInput("10"); ok {
		t.Fatal("did not expect option 10")
	}
}

func TestBuildNetworkDecisionMenu_HostOnly(t *testing.T) {
	menu := buildNetworkDecisionMenu("hackerman", "example.com", "example.com", true)
	if !menu.HostOnly {
		t.Fatal("expected host-only menu")
	}
	if len(menu.Options) != 6 {
		t.Fatalf("options len=%d want 6", len(menu.Options))
	}
	if menu.maxIndex() != 5 {
		t.Fatalf("maxIndex=%d want 5", menu.maxIndex())
	}
	got, ok := menu.selectByInput("2")
	if !ok {
		t.Fatal("expected option 2 to exist")
	}
	if got.Decision != AllowedOnce || got.Scope != AgentOnly || got.NetworkScope != NetworkScopeHost || got.Effect != PolicyPermit {
		t.Fatalf("option 2 mismatch: %+v", got)
	}
	got, ok = menu.selectByInput("5")
	if !ok {
		t.Fatal("expected option 5 to exist")
	}
	if got.Decision != Approved || got.Scope != AllAgents || got.NetworkScope != NetworkScopeHost || got.Effect != PolicyForbid {
		t.Fatalf("option 5 mismatch: %+v", got)
	}
}
