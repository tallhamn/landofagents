package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func runServe(args []string) {
	if len(args) == 0 {
		serveUsage()
		os.Exit(1)
	}
	switch strings.TrimSpace(args[0]) {
	case "control":
		runServeControl(args[1:])
	default:
		serveUsage()
		os.Exit(1)
	}
}

func serveUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  loa serve control [--socket <path>]
`)
}

func runServeControl(args []string) {
	fs := flag.NewFlagSet("serve control", flag.ExitOnError)
	socket := fs.String("socket", controlSocketPath(), "Unix socket path")
	fs.Parse(args)

	if err := serveControl(strings.TrimSpace(*socket)); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Error: serve control: %v\n", err)
		os.Exit(1)
	}
}
