// Package runtime manages pluggable agent runtime definitions.
//
// A runtime is a directory containing everything needed to run a specific type
// of agent (Dockerfile, entrypoint, base Cedar policies). LOA ships built-in
// runtimes via go:embed; users can customize after extraction with `loa init`.
package runtime

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/marcusmom/land-of-agents/engine/netscope"
	"gopkg.in/yaml.v3"
)

//go:embed runtimes
var embedded embed.FS

// Runtime describes an agent runtime definition.
type Runtime struct {
	Name            string           `yaml:"-"`
	Hook            string           `yaml:"hook,omitempty"`
	Build           *Build           `yaml:"build,omitempty"`
	Image           string           `yaml:"image,omitempty"`
	Env             []string         `yaml:"env,omitempty"`
	BaseCedar       string           `yaml:"base_cedar,omitempty"`
	BaseCedarBlocks []BaseCedarBlock `yaml:"base_cedar_blocks,omitempty"`
}

type BaseCedarBlock struct {
	AuthModes []string `yaml:"auth_modes,omitempty"`
	WhenEnv   []string `yaml:"when_env,omitempty"`
	Cedar     string   `yaml:"cedar,omitempty"`
}

// Build describes how to build the agent container image.
type Build struct {
	Dockerfile string   `yaml:"dockerfile"`
	Files      []string `yaml:"files,omitempty"`
}

// Load reads a runtime definition from a directory on disk.
func Load(dir string) (*Runtime, error) {
	data, err := os.ReadFile(filepath.Join(dir, "runtime.yml"))
	if err != nil {
		return nil, fmt.Errorf("read runtime.yml: %w", err)
	}

	var rt Runtime
	if err := yaml.Unmarshal(data, &rt); err != nil {
		return nil, fmt.Errorf("parse runtime.yml: %w", err)
	}
	rt.Name = filepath.Base(dir)
	if rt.Hook == "" {
		rt.Hook = rt.Name
	}

	if rt.Build == nil && rt.Image == "" {
		return nil, fmt.Errorf("runtime %q must define either build or image", rt.Name)
	}
	if rt.Build != nil && rt.Image != "" {
		return nil, fmt.Errorf("runtime %q defines both build and image (mutually exclusive)", rt.Name)
	}

	return &rt, nil
}

// ListEmbedded returns the names of all embedded runtimes.
func ListEmbedded() ([]string, error) {
	entries, err := embedded.ReadDir("runtimes")
	if err != nil {
		return nil, fmt.Errorf("read embedded runtimes: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// ExtractTo extracts an embedded runtime to destDir/<name>/.
// If the destination already exists, it is left untouched (user may have customized).
func ExtractTo(name, destDir string) error {
	target := filepath.Join(destDir, name)
	if _, err := os.Stat(target); err == nil {
		// Already exists — don't overwrite user customizations
		return nil
	}

	srcDir := filepath.Join("runtimes", name)
	return fs.WalkDir(embedded, srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Compute relative path from srcDir
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(target, rel)

		if d.IsDir() {
			return os.MkdirAll(dst, 0755)
		}

		data, err := embedded.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", path, err)
		}
		return os.WriteFile(dst, data, 0644)
	})
}

func (r *Runtime) RenderBaseCedar(authMode string) (string, error) {
	var blocks []string
	if text, err := renderBaseCedarText(r.BaseCedar); err != nil {
		return "", err
	} else if text != "" {
		blocks = append(blocks, text)
	}

	for _, block := range r.BaseCedarBlocks {
		if !block.matches(authMode) {
			continue
		}
		text, err := renderBaseCedarText(block.Cedar)
		if err != nil {
			return "", err
		}
		if text != "" {
			blocks = append(blocks, text)
		}
	}

	return strings.TrimSpace(strings.Join(blocks, "\n\n")), nil
}

func (b BaseCedarBlock) matches(authMode string) bool {
	if len(b.AuthModes) > 0 {
		matched := false
		for _, mode := range b.AuthModes {
			if strings.EqualFold(strings.TrimSpace(mode), strings.TrimSpace(authMode)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, name := range b.WhenEnv {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			return false
		}
	}
	return true
}

func renderBaseCedarText(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil
	}
	tmpl, err := template.New("base_cedar").Funcs(template.FuncMap{
		"env": func(name string) string {
			return strings.TrimSpace(os.Getenv(name))
		},
		"envDomain": func(name string) string {
			return envDomain(os.Getenv(name))
		},
	}).Parse(text)
	if err != nil {
		return "", fmt.Errorf("parse base_cedar template: %w", err)
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, nil); err != nil {
		return "", fmt.Errorf("render base_cedar template: %w", err)
	}
	return strings.TrimSpace(b.String()), nil
}

func envDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if slash := strings.IndexByte(raw, '/'); slash >= 0 {
		raw = raw[:slash]
	}
	if domain := netscope.EffectiveDomain(raw); domain != "" {
		return domain
	}
	return raw
}
