package contain

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marcusmom/land-of-agents/engine/runtime"
)

func TestWriteBaseCedar_WritesToRealKitDir(t *testing.T) {
	kitDir := t.TempDir()

	cedar := `permit(principal, action == Action::"http:Request", resource == Resource::"api.anthropic.com");`
	if err := writeBaseCedar(kitDir, "hackerman", cedar); err != nil {
		t.Fatalf("writeBaseCedar: %v", err)
	}

	// Must be in kitDir/policies/active/, NOT in any temp/kit copy
	policyFile := filepath.Join(kitDir, "policies", "active", "_runtime-hackerman.cedar")
	data, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatalf("policy file not found at %s: %v", policyFile, err)
	}
	if string(data) != cedar {
		t.Errorf("policy content: got %q", string(data))
	}
}

func TestTerminateAgentStacks_RemovesMatchingStack(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "docker.log")
	psOut := filepath.Join(tmp, "ps.out")
	if err := os.WriteFile(psOut, []byte(strings.Join([]string{
		"loa-contain-1001-hackerman-run-abc123",
		"loa-contain-1001-envoy-1",
		"loa-contain-1001-loa-authz-1",
		"loa-contain-7777-otheragent-run-xyz",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write ps output: %v", err)
	}

	dockerPath := filepath.Join(tmp, "docker")
	script := `#!/bin/sh
set -eu
printf "%s\n" "$*" >> "${FAKE_DOCKER_LOG}"
if [ "${1:-}" = "ps" ]; then
  cat "${FAKE_DOCKER_PS_OUTPUT}"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(dockerPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}

	t.Setenv("FAKE_DOCKER_LOG", logPath)
	t.Setenv("FAKE_DOCKER_PS_OUTPUT", psOut)
	t.Setenv("PATH", fmt.Sprintf("%s%c%s", tmp, os.PathListSeparator, os.Getenv("PATH")))

	n, err := TerminateAgentStacks("hackerman")
	if err != nil {
		t.Fatalf("TerminateAgentStacks: %v", err)
	}
	if n != 1 {
		t.Fatalf("terminated=%d want 1", n)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read docker log: %v", err)
	}
	out := string(logData)
	if strings.Count(out, "ps -a --format {{.Names}}") < 2 {
		t.Fatalf("expected two docker ps calls, got:\n%s", out)
	}
	if !strings.Contains(out, "rm -f loa-contain-1001-hackerman-run-abc123 loa-contain-1001-envoy-1 loa-contain-1001-loa-authz-1") {
		t.Fatalf("missing docker rm call for matching stack:\n%s", out)
	}
	if !strings.Contains(out, "network rm loa-contain-1001_agent-net") {
		t.Fatalf("missing agent-net remove call:\n%s", out)
	}
	if !strings.Contains(out, "network rm loa-contain-1001_external-net") {
		t.Fatalf("missing external-net remove call:\n%s", out)
	}
}

func TestRunComposeSession_InterruptTriggersDown(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "docker.log")
	composePath := filepath.Join(tmp, "docker-compose.yaml")
	if err := os.WriteFile(composePath, []byte("services: {}"), 0o644); err != nil {
		t.Fatalf("write compose fixture: %v", err)
	}

	dockerPath := filepath.Join(tmp, "docker")
	script := `#!/bin/sh
set -eu
printf "%s\n" "$*" >> "${FAKE_DOCKER_LOG}"
case "${1:-}" in
  compose)
    mode=""
    for arg in "$@"; do
      case "$arg" in
        up|run|down) mode="$arg"; break ;;
      esac
    done
    case "$mode" in
      up) exit 0 ;;
      down) exit 0 ;;
      run)
        trap 'exit 130' INT TERM
        while :; do sleep 1; done
        ;;
    esac
    ;;
esac
exit 0
`
	if err := os.WriteFile(dockerPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}

	t.Setenv("FAKE_DOCKER_LOG", logPath)
	t.Setenv("PATH", fmt.Sprintf("%s%c%s", tmp, os.PathListSeparator, os.Getenv("PATH")))

	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runComposeSession(composePath, append(os.Environ(), "FAKE_DOCKER_LOG="+logPath), "hackerman", sigCh)
	}()

	// Wait until the run command has started before simulating Ctrl-C.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		if strings.Contains(string(data), "compose -f "+composePath+" run --rm --service-ports hackerman") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sigCh <- syscall.SIGINT

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "agent interrupted") {
			t.Fatalf("expected agent interrupted error, got: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("runComposeSession did not return after interrupt")
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read docker log: %v", err)
	}
	out := string(logData)
	if !strings.Contains(out, "compose -f "+composePath+" up -d --build loa-authz envoy") {
		t.Fatalf("missing compose up call:\n%s", out)
	}
	if !strings.Contains(out, "compose -f "+composePath+" run --rm --service-ports hackerman") {
		t.Fatalf("missing compose run call:\n%s", out)
	}
	if !strings.Contains(out, "compose -f "+composePath+" down") {
		t.Fatalf("missing compose down teardown call:\n%s", out)
	}

	// Ensure no leftover signal handlers from this test channel path.
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
}

func TestWriteBaseCedar_SkipsEmpty(t *testing.T) {
	kitDir := t.TempDir()

	if err := writeBaseCedar(kitDir, "hackerman", ""); err != nil {
		t.Fatalf("writeBaseCedar: %v", err)
	}

	// policies/active dir should not even be created
	if _, err := os.Stat(filepath.Join(kitDir, "policies")); err == nil {
		t.Error("policies/ dir should not exist when cedar is empty")
	}
}

func TestWriteBaseCedar_CreatesPoliciesDir(t *testing.T) {
	kitDir := t.TempDir()

	cedar := "permit(principal, action, resource);"
	if err := writeBaseCedar(kitDir, "testbot", cedar); err != nil {
		t.Fatalf("writeBaseCedar: %v", err)
	}

	info, err := os.Stat(filepath.Join(kitDir, "policies", "active"))
	if err != nil {
		t.Fatal("policies/active dir not created")
	}
	if !info.IsDir() {
		t.Error("policies/active is not a directory")
	}
}

func TestGenerateCompose_EnvVarsFromRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yaml")

	err := generateCompose(path, composeData{
		AgentName:      "hackerman",
		KitDir:         "/home/user/kit",
		AgentPort:      9002,
		ProxyPort:      10000,
		Mode:           "enforce",
		UseBuild:       true,
		ManagedEnv:     []string{"CLAUDE_CONFIG_DIR=/home/node/.claude"},
		ManagedVolumes: []string{"/home/user/kit/workspaces/hackerman/.claude:/home/node/.claude"},
		EnvVars:        []string{"ANTHROPIC_API_KEY", "CUSTOM_TOKEN"},
	})
	if err != nil {
		t.Fatalf("generateCompose: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	content := string(data)

	// Env vars from runtime must appear in compose with ${} passthrough
	if !strings.Contains(content, "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}") {
		t.Error("missing ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY} in compose")
	}
	if !strings.Contains(content, "CUSTOM_TOKEN=${CUSTOM_TOKEN}") {
		t.Error("missing CUSTOM_TOKEN=${CUSTOM_TOKEN} in compose")
	}

	// Managed env entries from the runtime hook should appear in compose.
	if !strings.Contains(content, "CLAUDE_CONFIG_DIR=/home/node/.claude") {
		t.Error("missing CLAUDE_CONFIG_DIR in compose")
	}

	// Proxy env vars must always be present
	if !strings.Contains(content, "HTTP_PROXY=http://envoy:10000") {
		t.Error("missing HTTP_PROXY in compose")
	}

	// Managed runtime volume mount
	if !strings.Contains(content, "/home/user/kit/workspaces/hackerman/.claude:/home/node/.claude") {
		t.Error("missing persistent claude config volume mount")
	}
	if !strings.Contains(content, "/home/user/kit/audit:/etc/loa/audit:ro") {
		t.Error("missing read-only audit volume mount")
	}
}

func TestGenerateCompose_NoEnvVarsWhenEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker-compose.yaml")

	err := generateCompose(path, composeData{
		AgentName: "minimal",
		KitDir:    "/home/user/kit",
		AgentPort: 9002,
		ProxyPort: 10000,
		Mode:      "enforce",
		UseBuild:  true,
		EnvVars:   nil,
	})
	if err != nil {
		t.Fatalf("generateCompose: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)

	// Should NOT contain ANTHROPIC_API_KEY
	if strings.Contains(content, "ANTHROPIC_API_KEY") {
		t.Error("ANTHROPIC_API_KEY should not appear when EnvVars is nil")
	}
}

func TestGenerateCompose_BuildVsImage(t *testing.T) {
	t.Run("build mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "docker-compose.yaml")
		err := generateCompose(path, composeData{
			AgentName: "builder",
			KitDir:    "/kit",
			AgentPort: 9002,
			ProxyPort: 10000,
			Mode:      "enforce",
			UseBuild:  true,
		})
		if err != nil {
			t.Fatalf("generateCompose: %v", err)
		}

		data, _ := os.ReadFile(path)
		content := string(data)
		if !strings.Contains(content, "dockerfile: Dockerfile.agent") {
			t.Error("build mode should reference Dockerfile.agent")
		}
		if strings.Contains(content, "image: ") && strings.Contains(content, "agent:") {
			// The envoy service has "image: envoyproxy..." which is fine.
			// Just make sure the agent service uses build, not image.
		}
	})

	t.Run("image mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "docker-compose.yaml")
		err := generateCompose(path, composeData{
			AgentName:  "prebuilt",
			KitDir:     "/kit",
			AgentPort:  9002,
			ProxyPort:  10000,
			Mode:       "enforce",
			UseBuild:   false,
			AgentImage: "myregistry/myagent:latest",
		})
		if err != nil {
			t.Fatalf("generateCompose: %v", err)
		}

		data, _ := os.ReadFile(path)
		content := string(data)
		if !strings.Contains(content, "image: myregistry/myagent:latest") {
			t.Error("image mode should use the agent image")
		}
		if strings.Contains(content, "Dockerfile.agent") {
			t.Error("image mode should not reference Dockerfile.agent")
		}
	})
}

func TestResolveUserVolumes_UseOnlyExtraVolumes(t *testing.T) {
	agentVolumes := []string{
		"/srv/loa/shared:/shared:rw",
		"/srv/loa/projects:/projects:ro",
	}
	extraVolumes := []string{
		"/srv/loa/projects/subset:/projects/subset:ro",
	}
	got, err := resolveUserVolumes(agentVolumes, extraVolumes, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "/srv/loa/projects/subset:/projects/subset:ro" {
		t.Fatalf("volumes=%v", got)
	}
}

func TestResolveUserVolumes_MergeMode(t *testing.T) {
	agentVolumes := []string{
		"/srv/loa/shared:/shared:rw",
	}
	extraVolumes := []string{
		"/srv/loa/projects/subset:/projects/subset:ro",
	}
	got, err := resolveUserVolumes(agentVolumes, extraVolumes, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("volumes=%v", got)
	}
	if got[0] != "/srv/loa/shared:/shared:rw" || got[1] != "/srv/loa/projects/subset:/projects/subset:ro" {
		t.Fatalf("volumes order/content=%v", got)
	}
}

func TestResolveUserVolumes_SkipsManagedTargetConflicts(t *testing.T) {
	agentVolumes := []string{
		"/srv/loa/shared:/workspace:rw",
		"/srv/loa/logs:/logs:rw",
	}
	got, err := resolveUserVolumes(agentVolumes, nil, []string{"/workspace"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "/srv/loa/logs:/logs:rw" {
		t.Fatalf("volumes=%v", got)
	}
}

func TestVolumeConflictFiltering(t *testing.T) {
	tests := []struct {
		name     string
		volumes  []string
		expected []string
	}{
		{
			name:     "filters claude config mount",
			volumes:  []string{"~/.loa-agents/hackerman:/home/node/.claude", "/data:/workspace"},
			expected: []string{"/data:/workspace"},
		},
		{
			name:     "keeps non-conflicting volumes",
			volumes:  []string{"/data:/workspace", "/config:/app/config"},
			expected: []string{"/data:/workspace", "/config:/app/config"},
		},
		{
			name:     "filters with :ro suffix",
			volumes:  []string{"/foo:/home/node/.claude:ro", "/data:/workspace"},
			expected: []string{"/data:/workspace"},
		},
		{
			name:     "empty when all filtered",
			volumes:  []string{"/foo:/home/node/.claude"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filtered []string
			for _, v := range tt.volumes {
				expanded := expandTildeVolume(v)
				if volumeConflictsWithTargets(expanded, []string{"/home/node/.claude"}) {
					continue
				}
				filtered = append(filtered, expanded)
			}

			if len(filtered) != len(tt.expected) {
				t.Fatalf("got %d volumes, want %d: %v", len(filtered), len(tt.expected), filtered)
			}
			for i, v := range filtered {
				if v != tt.expected[i] {
					t.Errorf("volume[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestContainerMountPath(t *testing.T) {
	tests := []struct {
		volume string
		want   string
	}{
		{volume: "/host/path:/workspace", want: "/workspace"},
		{volume: "/host/path:/workspace:ro", want: "/workspace"},
		{volume: "C:\\\\host\\\\path:/workspace", want: "/workspace"},
		{volume: "relative-path", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.volume, func(t *testing.T) {
			if got := containerMountPath(tt.volume); got != tt.want {
				t.Fatalf("containerMountPath(%q) = %q, want %q", tt.volume, got, tt.want)
			}
		})
	}
}

func TestCopyRuntimeFiles(t *testing.T) {
	// Set up a fake kit with a runtime
	kitDir := t.TempDir()
	rtDir := filepath.Join(kitDir, "runtimes", "test-rt")
	os.MkdirAll(rtDir, 0755)
	os.WriteFile(filepath.Join(rtDir, "Dockerfile"), []byte("FROM alpine"), 0644)
	os.WriteFile(filepath.Join(rtDir, "entrypoint.sh"), []byte("#!/bin/sh"), 0644)
	os.WriteFile(filepath.Join(rtDir, "helper.js"), []byte("// helper"), 0644)

	rt := &runtime.Runtime{
		Name: "test-rt",
		Build: &runtime.Build{
			Dockerfile: "Dockerfile",
			Files:      []string{"entrypoint.sh", "helper.js"},
		},
	}

	tmpDir := t.TempDir()
	if err := copyRuntimeFiles(rt, kitDir, tmpDir); err != nil {
		t.Fatalf("copyRuntimeFiles: %v", err)
	}

	// Dockerfile copied as Dockerfile.agent
	if _, err := os.Stat(filepath.Join(tmpDir, "Dockerfile.agent")); err != nil {
		t.Error("Dockerfile.agent not found in temp dir")
	}

	// Additional files copied by name
	if _, err := os.Stat(filepath.Join(tmpDir, "entrypoint.sh")); err != nil {
		t.Error("entrypoint.sh not found in temp dir")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "helper.js")); err != nil {
		t.Error("helper.js not found in temp dir")
	}
}

func TestComposePrefixFromRunContainerName(t *testing.T) {
	tests := []struct {
		name      string
		container string
		agent     string
		want      string
		ok        bool
	}{
		{
			name:      "valid",
			container: "loa-contain-1866230990-hackerman-run-ce27afc0a476",
			agent:     "hackerman",
			want:      "loa-contain-1866230990",
			ok:        true,
		},
		{
			name:      "wrong agent",
			container: "loa-contain-1866230990-goggins-run-abcd",
			agent:     "hackerman",
			want:      "",
			ok:        false,
		},
		{
			name:      "non run container",
			container: "loa-contain-1866230990-loa-authz-1",
			agent:     "hackerman",
			want:      "",
			ok:        false,
		},
		{
			name:      "non loa container",
			container: "random-container",
			agent:     "hackerman",
			want:      "",
			ok:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := composePrefixFromRunContainerName(tt.container, tt.agent)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tt.ok, got)
			}
			if got != tt.want {
				t.Fatalf("prefix = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCopyRuntimeFiles_ImageRuntime(t *testing.T) {
	rt := &runtime.Runtime{
		Name:  "prebuilt",
		Image: "alpine:latest",
	}

	tmpDir := t.TempDir()
	if err := copyRuntimeFiles(rt, "/nonexistent", tmpDir); err != nil {
		t.Fatalf("copyRuntimeFiles should succeed for image runtime: %v", err)
	}

	// Nothing should be copied
	entries, _ := os.ReadDir(tmpDir)
	if len(entries) != 0 {
		t.Errorf("expected empty tmpDir for image runtime, got %d files", len(entries))
	}
}

func TestResolveModuleRoot_OverrideWins(t *testing.T) {
	moduleRoot := makeFakeModuleRoot(t)
	start := t.TempDir()
	got := resolveModuleRoot(start, moduleRoot, "")
	if got != moduleRoot {
		t.Fatalf("resolveModuleRoot override = %q, want %q", got, moduleRoot)
	}
}

func TestResolveModuleRoot_FindsUpward(t *testing.T) {
	moduleRoot := makeFakeModuleRoot(t)
	start := filepath.Join(moduleRoot, "internal", "contain")
	if err := os.MkdirAll(start, 0755); err != nil {
		t.Fatalf("mkdir start: %v", err)
	}
	got := resolveModuleRoot(start, "", "")
	if got != moduleRoot {
		t.Fatalf("resolveModuleRoot upward = %q, want %q", got, moduleRoot)
	}
}

func TestResolveModuleRoot_FindsDownwardFromParentWorkspace(t *testing.T) {
	workspace := t.TempDir()
	moduleRoot := filepath.Join(workspace, "land-of-agents")
	if err := os.MkdirAll(moduleRoot, 0755); err != nil {
		t.Fatalf("mkdir module root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/loa\n"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(moduleRoot, "cmd", "loa"), 0755); err != nil {
		t.Fatalf("mkdir cmd/loa: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "cmd", "loa", "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatalf("write cmd/loa/main.go: %v", err)
	}
	got := resolveModuleRoot(workspace, "", "")
	if got != moduleRoot {
		t.Fatalf("resolveModuleRoot downward = %q, want %q", got, moduleRoot)
	}
}

func TestResolveModuleRoot_FallsBackDotWhenMissing(t *testing.T) {
	got := resolveModuleRoot(t.TempDir(), "", "")
	if got != "." {
		t.Fatalf("resolveModuleRoot fallback = %q, want .", got)
	}
}

func makeFakeModuleRoot(t *testing.T) string {
	t.Helper()
	moduleRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(moduleRoot, "go.mod"), []byte("module example.com/loa\n"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(moduleRoot, "cmd", "loa"), 0755); err != nil {
		t.Fatalf("mkdir cmd/loa: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moduleRoot, "cmd", "loa", "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatalf("write cmd/loa/main.go: %v", err)
	}
	return moduleRoot
}

func TestValidateHostPath(t *testing.T) {
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"/home/user/code", false},
		{"/srv/loa/data", false},
		{"/home/user/etc-backup", false},
		{"/", true},
		{"/etc", true},
		{"/etc/ssh", true},
		{"/proc", true},
		{"/proc/1/root", true},
		{"/sys", true},
		{"/sys/fs/cgroup", true},
		{"/dev", true},
		{"/dev/kmsg", true},
		{"/boot", true},
		{"/boot/efi", true},
		{"/var/run/docker.sock", true},
		{"/run/docker.sock", true},
		{"/etc/../etc", true},            // path traversal
		{"/home/user/../../../etc", true}, // path traversal
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := validateHostPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHostPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestResolveUserVolumes_RejectsForbiddenPaths(t *testing.T) {
	_, err := resolveUserVolumes([]string{"/etc:/container/etc:ro"}, nil, nil, false)
	if err == nil {
		t.Fatal("expected error for /etc mount, got nil")
	}

	_, err = resolveUserVolumes([]string{"/var/run/docker.sock:/var/run/docker.sock"}, nil, nil, false)
	if err == nil {
		t.Fatal("expected error for docker socket mount, got nil")
	}

	_, err = resolveUserVolumes([]string{"/etc/ssh:/container/etc-ssh:ro"}, nil, nil, false)
	if err == nil {
		t.Fatal("expected error for /etc subtree mount, got nil")
	}

	vols, err := resolveUserVolumes([]string{"/home/user/code:/workspace:rw"}, nil, nil, false)
	if err != nil {
		t.Fatalf("unexpected error for safe path: %v", err)
	}
	if len(vols) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(vols))
	}
}
