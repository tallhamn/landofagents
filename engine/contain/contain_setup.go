package contain

import (
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"text/template"

	"github.com/marcusmom/land-of-agents/engine/config"
	"github.com/marcusmom/land-of-agents/engine/runtimehooks"
	"github.com/marcusmom/land-of-agents/engine/secrets"
)

// SetupEnvironment prepares the Docker compose environment without starting it.
// Returns paths needed to run or manage the compose setup.
func SetupEnvironment(opts Options) (*Environment, error) {
	if opts.AgentPort == 0 {
		opts.AgentPort = 9002
	}
	if opts.ProxyPort == 0 {
		opts.ProxyPort = 10000
	}
	logOut := opts.LogOut
	if logOut == nil {
		logOut = os.Stdout
	}

	kit, err := config.LoadKit(opts.KitDir)
	if err != nil {
		return nil, fmt.Errorf("load kit: %w", err)
	}
	agentConfig, err := kit.GetAgent(opts.AgentName)
	if err != nil {
		return nil, err
	}

	rt, err := kit.LoadAgentRuntime(opts.AgentName)
	if err != nil {
		return nil, fmt.Errorf("load runtime: %w", err)
	}
	hook := runtimehooks.ForRuntime(rt.Hook)

	runtimeEnv := append([]string{}, rt.Env...)
	authMode := ""
	var managedEnv []string
	var managedVolumes []string

	kitDir, err := filepath.Abs(opts.KitDir)
	if err != nil {
		return nil, fmt.Errorf("resolve kit dir: %w", err)
	}

	managedTargets := hook.ManagedMountTargets()
	volumes, err := resolveUserVolumes(agentConfig.Volumes, opts.ExtraVolumes, managedTargets, opts.UseOnlyExtraVolumes)
	if err != nil {
		return nil, fmt.Errorf("resolve volumes: %w", err)
	}

	workspaceDir := filepath.Join(kitDir, "workspaces", opts.AgentName)
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		return nil, fmt.Errorf("create workspace dir: %w", err)
	}

	prepared, err := hook.Prepare(runtimehooks.PrepareInput{
		WorkspaceDir: workspaceDir,
		RuntimeEnv:   runtimeEnv,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare runtime %q: %w", rt.Name, err)
	}
	runtimeEnv = prepared.RuntimeEnv

	reg, err := secrets.LoadRegistry(kitDir)
	if err != nil {
		return nil, fmt.Errorf("load secret registry: %w", err)
	}
	secretRole := secrets.NormalizeRole(opts.SecretRole)
	if secretRole == "" {
		secretRole = secrets.RoleGateway
	}
	selectedSecretRefs := append([]string{}, agentConfig.AllowedSecrets...)
	if opts.SecretRefs != nil {
		selectedSecretRefs = secrets.NormalizeRefs(opts.SecretRefs)
		missingRefs := secrets.MissingAllowedRefs(selectedSecretRefs, agentConfig.AllowedSecrets)
		if len(missingRefs) > 0 {
			return nil, fmt.Errorf("apply secret refs override: requested secret ref %q is not allowed for this agent", missingRefs[0])
		}
	}
	if err := ensureSecretRefsExposedToRole(reg, selectedSecretRefs, secretRole); err != nil {
		return nil, fmt.Errorf("apply secret role policy: %w", err)
	}
	secretEnv, missingSecretRefs := reg.ResolveAllowedEnvFromRefs(selectedSecretRefs)
	if len(missingSecretRefs) > 0 {
		return nil, fmt.Errorf("agent %q references undefined secrets: %s", opts.AgentName, strings.Join(missingSecretRefs, ", "))
	}
	allowlist := append([]string{}, agentConfig.AllowedEnv...)
	allowlist = append(allowlist, secretEnv...)
	explicitSecretPolicy := len(secrets.NormalizeAllowlist(agentConfig.AllowedEnv)) > 0 || len(agentConfig.AllowedSecrets) > 0
	runtimeEnv, _ = secrets.FilterDeclaredEnvStrict(runtimeEnv, allowlist, explicitSecretPolicy)
	authMode = prepared.AuthMode
	managedEnv = prepared.AgentEnv
	managedVolumes = prepared.AgentVolumes

	tmpDir, err := os.MkdirTemp("", "loa-contain-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	fmt.Fprintf(logOut, "Setup dir: %s\n", tmpDir)
	runID := filepath.Base(tmpDir)

	fmt.Fprintf(logOut, "Building loa for linux/%s...\n", goruntime.GOARCH)
	loaBinary := filepath.Join(tmpDir, "loa")
	if err := buildLoa(loaBinary); err != nil {
		return nil, fmt.Errorf("build loa: %w", err)
	}

	kitCopy := filepath.Join(tmpDir, "kit")
	if err := copyKitConfig(kitDir, kitCopy); err != nil {
		return nil, fmt.Errorf("copy kit: %w", err)
	}

	if err := writeBaseCedar(kitDir, opts.AgentName, rt.BaseCedar); err != nil {
		return nil, err
	}

	authzTimeoutMs := 14400000 // 4 hours — authz responds fast for allow/deny, only holds for gate
	envoyConfig := filepath.Join(tmpDir, "envoy.yaml")
	srcEnvoy := filepath.Join(kitDir, "..", "configs", "envoy.yaml.tmpl")
	if _, err := os.Stat(srcEnvoy); os.IsNotExist(err) {
		srcEnvoy = findEnvoyConfig()
	}
	envoyData, err := os.ReadFile(srcEnvoy)
	if err != nil {
		return nil, fmt.Errorf("read envoy template: %w", err)
	}
	envoyTmpl, err := template.New("envoy").Parse(string(envoyData))
	if err != nil {
		return nil, fmt.Errorf("parse envoy template: %w", err)
	}
	envoyOut, err := os.Create(envoyConfig)
	if err != nil {
		return nil, fmt.Errorf("create envoy config: %w", err)
	}
	if err := envoyTmpl.Execute(envoyOut, struct{ AuthzTimeoutMs int }{authzTimeoutMs}); err != nil {
		envoyOut.Close()
		return nil, fmt.Errorf("render envoy template: %w", err)
	}
	envoyOut.Close()

	authzDockerfileSrc := filepath.Join(filepath.Dir(srcEnvoy), "Dockerfile.authz")
	if err := copyFile(authzDockerfileSrc, filepath.Join(tmpDir, "Dockerfile.authz")); err != nil {
		return nil, fmt.Errorf("copy Dockerfile.authz: %w", err)
	}

	if err := copyRuntimeFiles(rt, kitDir, tmpDir); err != nil {
		return nil, fmt.Errorf("copy runtime files: %w", err)
	}

	composePath := filepath.Join(tmpDir, "docker-compose.yaml")
	if err := generateCompose(composePath, composeData{
		AgentName:      opts.AgentName,
		RunID:          runID,
		Volumes:        volumes,
		ManagedEnv:     managedEnv,
		ManagedVolumes: managedVolumes,
		KitDir:         kitDir,
		AgentPort:      opts.AgentPort,
		ProxyPort:      opts.ProxyPort,
		Mode:           opts.Mode,
		UseBuild:       rt.Build != nil,
		AgentImage:     rt.Image,
		EnvVars:        runtimeEnv,
	}); err != nil {
		return nil, fmt.Errorf("generate compose: %w", err)
	}

	return &Environment{
		TmpDir:      tmpDir,
		ComposePath: composePath,
		KitDir:      kitDir,
		RuntimeEnv:  runtimeEnv,
		AuthMode:    authMode,
	}, nil
}

func ensureSecretRefsExposedToRole(reg *secrets.Registry, refs []string, role string) error {
	if len(refs) == 0 {
		return nil
	}
	denied := reg.RefsNotExposedToRole(refs, role)
	if len(denied) == 0 {
		return nil
	}
	return fmt.Errorf("requested secret refs are not exposed to role %q: %s", role, strings.Join(denied, ", "))
}
