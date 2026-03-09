package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/runtime"
)

func runInit(args []string) {
	dir := kitDir()

	// Create directory structure
	dirs := []string{
		filepath.Join(dir, "config"),
		filepath.Join(dir, "policies"),
		filepath.Join(dir, "policies", "staged"),
		filepath.Join(dir, "policies", "active"),
		filepath.Join(dir, "runtimes"),
		filepath.Join(dir, "audit"),
		filepath.Join(dir, "tests"),
		filepath.Join(dir, "workspaces"),
		filepath.Join(dir, "workers"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", d, err)
			os.Exit(1)
		}
	}

	// Write default always-allowed.cedar (generic — no runtime-specific policies)
	alwaysAllowed := filepath.Join(dir, "config", "always-allowed.cedar")
	if _, err := os.Stat(alwaysAllowed); os.IsNotExist(err) {
		os.WriteFile(alwaysAllowed, []byte(`// Safe floor — what agents can always do

// All agents can read local files
permit(
  principal,
  action == Action::"fs:Read",
  resource
);
`), 0644)
	}

	// Write default protector.yml
	protectorYml := filepath.Join(dir, "config", "protector.yml")
	if _, err := os.Stat(protectorYml); os.IsNotExist(err) {
		os.WriteFile(protectorYml, []byte(`tool_mappings:
  - executable: "cat"
    action: "fs:Read"
    resource_extractor: "first_arg"
  - executable: "ls"
    action: "fs:List"
    resource_extractor: "first_arg"
  - executable: "grep"
    action: "fs:Read"
    resource_extractor: "first_arg"
  - executable: "curl"
    action: "http:Request"
    resource_extractor: "domain_from_url"
  - executable: "git"
    action: "git:Command"
  - executable: "python"
    action: "sandbox:RunScript"
  - executable: "python3"
    action: "sandbox:RunScript"
  - executable: "node"
    action: "sandbox:RunScript"
  - executable: "go"
    action: "sandbox:RunScript"
  - pattern: "* | bash"
    action: "__deny_always"
  - pattern: "* | sh"
    action: "__deny_always"
  - pattern: "eval *"
    action: "__deny_always"

default_unmapped: deny

audit:
  log_dir: audit/
  format: jsonl
  log_permitted: true
  log_denied: true
  log_always_allowed: false
`), 0644)
	}

	// Write default secrets.yml registry
	secretsYml := filepath.Join(dir, "config", "secrets.yml")
	if _, err := os.Stat(secretsYml); os.IsNotExist(err) {
		os.WriteFile(secretsYml, []byte("secrets: {}\n"), 0644)
	}

	// Write default principals.yml for GAP control-plane identity binding.
	principalsYml := filepath.Join(dir, "config", "principals.yml")
	if _, err := os.Stat(principalsYml); os.IsNotExist(err) {
		os.WriteFile(principalsYml, []byte(fmt.Sprintf(`principals:
  - id: operator:local
    uid: %d
    allow_agents:
      - "*"
`, os.Getuid())), 0644)
	}

	// Extract embedded runtimes
	runtimesDir := filepath.Join(dir, "runtimes")
	names, err := runtime.ListEmbedded()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not list embedded runtimes: %v\n", err)
	}
	for _, name := range names {
		if err := runtime.ExtractTo(name, runtimesDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not extract runtime %s: %v\n", name, err)
		}
	}

	fmt.Printf("Created %s/\n", dir)
	fmt.Printf("  config/always-allowed.cedar  — agents can read files\n")
	fmt.Printf("  config/protector.yml         — default tool mappings\n")
	fmt.Printf("  config/secrets.yml           — named secret definitions\n")
	fmt.Printf("  config/principals.yml        — uid to principal/agent mapping\n")
	if len(names) > 0 {
		fmt.Printf("  runtimes/                    — %s\n", strings.Join(names, ", "))
	}
	fmt.Printf("\nNext: loa agent create <name> --runtime claude-code\n")
}
