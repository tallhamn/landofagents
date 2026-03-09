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

	"gopkg.in/yaml.v3"
)

//go:embed runtimes
var embedded embed.FS

// Runtime describes an agent runtime definition.
type Runtime struct {
	Name      string   `yaml:"-"`
	Hook      string   `yaml:"hook,omitempty"`
	Build     *Build   `yaml:"build,omitempty"`
	Image     string   `yaml:"image,omitempty"`
	Env       []string `yaml:"env,omitempty"`
	BaseCedar string   `yaml:"base_cedar,omitempty"`
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
