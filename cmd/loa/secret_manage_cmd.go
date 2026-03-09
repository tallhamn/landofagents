package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/marcusmom/land-of-agents/engine/secrets"
)

func runSecretList(args []string) {
	reg, err := secrets.LoadRegistry(kitDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	refs := reg.ListRefs()
	fmt.Printf("Secrets (%d):\n", len(refs))
	if len(refs) == 0 {
		fmt.Printf("  (none)\n")
		return
	}
	for _, ref := range refs {
		def := reg.Secrets[ref]
		roles := strings.Join(secrets.EffectiveRoles(def), ",")
		if strings.TrimSpace(def.Description) == "" {
			fmt.Printf("  - %s -> %s [%s]\n", ref, def.Env, roles)
		} else {
			fmt.Printf("  - %s -> %s [%s] (%s)\n", ref, def.Env, roles, def.Description)
		}
	}
}

func runSecretSet(args []string) {
	var name string
	var flagArgs []string
	for _, a := range args {
		if name == "" && !isFlag(a) {
			name = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	if strings.TrimSpace(name) == "" {
		fmt.Fprintf(os.Stderr, "Usage: loa secret set <name> --env <ENV_VAR> [--description <text>] [--role gateway|worker]\n")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("secret set", flag.ExitOnError)
	envVar := fs.String("env", "", "Host env var source")
	description := fs.String("description", "", "Optional description")
	var roles roleFlag
	fs.Var(&roles, "role", "Secret exposure role (gateway|worker). Repeatable or comma-separated.")
	fs.Parse(flagArgs)

	if strings.TrimSpace(*envVar) == "" {
		fmt.Fprintf(os.Stderr, "Error: --env is required\n")
		os.Exit(1)
	}

	kit := kitDir()
	reg, err := secrets.LoadRegistry(kit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	ref := secrets.NormalizeRef(name)
	selectedRoles := roles.values
	if !roles.set {
		if existing, ok := reg.Secrets[ref]; ok && len(existing.Roles) > 0 {
			selectedRoles = append([]string{}, existing.Roles...)
		} else {
			selectedRoles = []string{secrets.RoleGateway}
		}
	}
	if err := reg.SetDefinition(name, *envVar, *description, selectedRoles); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := reg.Save(kit); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	def := reg.Secrets[ref]
	fmt.Printf("Saved secret: %s -> %s [%s]\n", ref, strings.ToUpper(strings.TrimSpace(*envVar)), strings.Join(secrets.EffectiveRoles(def), ","))
}

func runSecretDelete(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa secret delete <name>\n")
		os.Exit(1)
	}
	ref := secrets.NormalizeRef(args[0])
	if ref == "" {
		fmt.Fprintf(os.Stderr, "Error: secret name is required\n")
		os.Exit(1)
	}

	kit := kitDir()
	reg, err := secrets.LoadRegistry(kit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if !reg.DeleteDefinition(ref) {
		fmt.Fprintf(os.Stderr, "Error: secret %q not found\n", ref)
		os.Exit(1)
	}
	if err := reg.Save(kit); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Deleted secret: %s\n", ref)
}


type roleFlag struct {
	values []string
	set    bool
}

func (r *roleFlag) String() string {
	if len(r.values) == 0 {
		return ""
	}
	return strings.Join(r.values, ",")
}

func (r *roleFlag) Set(value string) error {
	r.set = true
	for _, part := range strings.Split(value, ",") {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		r.values = append(r.values, v)
	}
	r.values = uniqueStrings(r.values)
	return nil
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		key := strings.ToLower(strings.TrimSpace(raw))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, raw)
	}
	sort.Strings(out)
	return out
}
