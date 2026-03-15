package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/agent"
	"github.com/marcusmom/land-of-agents/engine/runtime"
)

func runAgent(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa agent <create|delete|list> [arguments]\n")
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		runAgentCreate(args[1:])
	case "delete":
		runAgentDelete(args[1:])
	case "list":
		runAgentList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown agent subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

// volumeFlags collects repeatable --volume flags.
type volumeFlags []string

func (v *volumeFlags) String() string { return fmt.Sprintf("%v", *v) }
func (v *volumeFlags) Set(val string) error {
	*v = append(*v, val)
	return nil
}

func runAgentCreate(args []string) {
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !isFlag(a) {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	if name == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa agent create <name> --runtime <runtime> [--volume <src>:<dst>] [--allow-env VAR] [--allow-secret REF]\n")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("agent create", flag.ExitOnError)
	rtName := fs.String("runtime", "claude-code", "Runtime for the agent (see runtimes/)")
	modeName := fs.String("mode", "", "Policy mode: ask (default), log, or enforce")
	var volumes volumeFlags
	var allowedEnv volumeFlags
	var allowedSecrets volumeFlags
	fs.Var(&volumes, "volume", "Volume mount (repeatable, e.g. ./code:/workspace)")
	fs.Var(&allowedEnv, "allow-env", "Allow runtime env var passthrough for this agent (repeatable)")
	fs.Var(&allowedSecrets, "allow-secret", "Allow named secret reference for this agent (repeatable)")
	fs.Parse(flagArgs)

	opts := agent.CreateOpts{
		Runtime:        *rtName,
		Mode:           *modeName,
		Volumes:        volumes,
		AllowedEnv:     allowedEnv,
		AllowedSecrets: allowedSecrets,
	}

	mgr := agent.NewManager(kitDir())
	if err := mgr.Create(name, opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created agent: %s\n", name)
	fmt.Printf("  Runtime: %s\n", opts.Runtime)
	fmt.Printf("  Scope: %s\n", name)
	if len(volumes) > 0 {
		fmt.Printf("  Volumes:\n")
		for _, v := range volumes {
			fmt.Printf("    %s\n", v)
		}
	}
	if len(allowedEnv) > 0 {
		fmt.Printf("  Allowed env:\n")
		for _, e := range allowedEnv {
			fmt.Printf("    %s\n", e)
		}
	}
	if len(allowedSecrets) > 0 {
		fmt.Printf("  Allowed secrets:\n")
		for _, s := range allowedSecrets {
			fmt.Printf("    %s\n", s)
		}
	}
}

func runAgentDelete(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa agent delete <name>\n")
		os.Exit(1)
	}
	name := args[0]

	mgr := agent.NewManager(kitDir())
	if err := mgr.Delete(name); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Deleted agent: %s\n", name)
}

func runAgentList(args []string) {
	mgr := agent.NewManager(kitDir())
	agents, err := mgr.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(agents) == 0 {
		fmt.Println("No agents. Create one with: loa agent create <name> --runtime claude-code")
		return
	}

	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })

	// Resolve runtime image description for each agent.
	kit := kitDir()
	runtimesDir := kit + "/runtimes"
	imageCache := map[string]string{}
	resolveImage := func(rtName string) string {
		if v, ok := imageCache[rtName]; ok {
			return v
		}
		rt, err := runtime.Load(runtimesDir + "/" + rtName)
		if err != nil {
			imageCache[rtName] = "?"
			return "?"
		}
		var desc string
		if rt.Build != nil {
			base := dockerfileBaseImage(runtimesDir+"/"+rtName, rt.Build.Dockerfile)
			desc = "builds from " + base
		} else if rt.Image != "" {
			if isRegistryImage(rt.Image) {
				desc = qualifyImageRef(rt.Image)
			} else {
				parent := dockerImageParent(rt.Image)
				if parent != "" && parent != "?" {
					desc = rt.Image + " (local, from " + parent + ")"
				} else {
					desc = rt.Image + " (local)"
				}
			}
		}
		imageCache[rtName] = desc
		return desc
	}

	// Pre-resolve all so we can compute column widths.
	images := make([]string, len(agents))
	maxName, maxScope, maxRT := 5, 12, 7
	for i, a := range agents {
		images[i] = resolveImage(a.Runtime)
		if len(a.Name) > maxName {
			maxName = len(a.Name)
		}
		if len(a.Scope) > maxScope {
			maxScope = len(a.Scope)
		}
		if len(a.Runtime) > maxRT {
			maxRT = len(a.Runtime)
		}
	}

	fmt.Printf("  %-*s  %-*s  %-*s  %s\n", maxName, "AGENT", maxScope, "POLICY SCOPE", maxRT, "RUNTIME", "IMAGE")
	for i, a := range agents {
		fmt.Printf("  %-*s  %-*s  %-*s  %s\n", maxName, a.Name, maxScope, a.Scope, maxRT, a.Runtime, images[i])
	}
}

// isRegistryImage returns true if the image reference looks like a registry image
// (contains a dot in the first path component, e.g. ghcr.io/foo/bar:latest).
func isRegistryImage(ref string) bool {
	if i := strings.IndexByte(ref, '/'); i > 0 {
		return strings.Contains(ref[:i], ".")
	}
	return false
}

// dockerfileBaseImage reads the FROM line of a Dockerfile and fully qualifies it.
func dockerfileBaseImage(rtDir, dockerfile string) string {
	data, err := os.ReadFile(rtDir + "/" + dockerfile)
	if err != nil {
		return "?"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			return qualifyImageRef(strings.Fields(line)[1])
		}
	}
	return "?"
}

// dockerImageParent finds the immediate parent of a Docker image by matching
// layers against known registry images on the system. Returns the best match
// (longest layer prefix match) or falls back to OCI labels / "?".
func dockerImageParent(image string) string {
	// Registry images don't need a parent — they ARE the source of truth.
	if i := strings.IndexByte(image, '/'); i > 0 && strings.Contains(image[:i], ".") {
		return "-"
	}
	targetLayers := dockerImageLayers(image)
	if len(targetLayers) == 0 {
		return "?"
	}
	// Collect candidate parent images: all registry images on the system.
	out, err := exec.Command("docker", "images", "--format", "{{.Repository}}:{{.Tag}}", "--no-trunc").Output()
	if err != nil {
		return "?"
	}
	bestMatch := ""
	bestMatchLen := 0
	for _, candidate := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || candidate == image || candidate == "<none>:<none>" {
			continue
		}
		// Only consider registry images as potential parents.
		if i := strings.IndexByte(candidate, '/'); i <= 0 || !strings.Contains(candidate[:i], ".") {
			continue
		}
		candidateLayers := dockerImageLayers(candidate)
		if len(candidateLayers) == 0 || len(candidateLayers) >= len(targetLayers) {
			continue
		}
		// Check if candidate's layers are a prefix of target's layers.
		match := true
		for j, l := range candidateLayers {
			if l != targetLayers[j] {
				match = false
				break
			}
		}
		if match && len(candidateLayers) > bestMatchLen {
			bestMatch = candidate
			bestMatchLen = len(candidateLayers)
		}
	}
	if bestMatch != "" {
		return bestMatch
	}
	// Fall back to OCI label.
	labelOut, err := exec.Command("docker", "inspect", image,
		"--format", `{{index .Config.Labels "org.opencontainers.image.base.name"}}`).Output()
	if err == nil {
		base := strings.TrimSpace(string(labelOut))
		if base != "" && base != "<no value>" {
			return qualifyImageRef(base)
		}
	}
	return "?"
}

// dockerImageLayers returns the layer digests for a Docker image.
func dockerImageLayers(image string) []string {
	out, err := exec.Command("docker", "inspect", image, "--format", "{{json .RootFS.Layers}}").Output()
	if err != nil {
		return nil
	}
	var layers []string
	if json.Unmarshal(out, &layers) != nil {
		return nil
	}
	return layers
}

// qualifyImageRef ensures an image reference is fully qualified with registry and namespace.
func qualifyImageRef(ref string) string {
	if ref == "" || ref == "?" {
		return ref
	}
	firstSlash := strings.IndexByte(ref, '/')
	if firstSlash > 0 && strings.Contains(ref[:firstSlash], ".") {
		return ref
	}
	if firstSlash < 0 {
		return "docker.io/library/" + ref
	}
	return "docker.io/" + ref
}
