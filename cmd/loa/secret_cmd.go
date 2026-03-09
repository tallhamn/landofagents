package main

import (
	"fmt"
	"os"
)

func runSecret(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: loa secret <list|set|delete|grant|revoke> [arguments]\n")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		runSecretList(args[1:])
	case "set":
		runSecretSet(args[1:])
	case "delete":
		runSecretDelete(args[1:])
	case "grant":
		runSecretGrant(args[1:])
	case "revoke":
		runSecretRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown secret subcommand: %s\n", args[0])
		os.Exit(1)
	}
}
