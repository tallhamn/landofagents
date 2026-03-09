package main

import (
	"os"
	"path/filepath"
)

// kitDir returns the LOA kit directory. Checks $LOA_KIT, then defaults to ~/land-of-agents/.
func kitDir() string {
	if env := os.Getenv("LOA_KIT"); env != "" {
		return env
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "land-of-agents")
}
