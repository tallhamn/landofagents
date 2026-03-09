package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func loadYAML(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, v)
}

func addPolicyFiles(out *[]string, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read policy dir %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".cedar" {
			*out = append(*out, filepath.Join(dir, entry.Name()))
			continue
		}
		if ext == ".yml" || ext == ".yaml" {
			return fmt.Errorf("unsupported policy file format %q in %s: use .cedar", entry.Name(), dir)
		}
	}
	return nil
}
