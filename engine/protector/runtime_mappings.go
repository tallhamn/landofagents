package protector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/config"
	"gopkg.in/yaml.v3"
)

type runtimeMappingsFile struct {
	ToolMappings []config.ToolMapping `yaml:"tool_mappings"`
}

func loadRuntimeToolMappings(kitDir, runtimeName string) ([]config.ToolMapping, error) {
	runtimeName = filepath.Clean(runtimeName)
	if runtimeName == "" || runtimeName == "." || runtimeName == string(filepath.Separator) {
		return nil, nil
	}
	path := filepath.Join(kitDir, "runtimes", runtimeName, "command-mappings.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var parsed runtimeMappingsFile
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return parsed.ToolMappings, nil
}

func isStrictCommandModeEnabled() bool {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LOA_COMMAND_STRICT_MODE")))
	switch mode {
	case "1", "true", "on", "strict":
		return true
	default:
		return false
	}
}
