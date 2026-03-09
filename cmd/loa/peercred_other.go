//go:build !linux

package main

import (
	"net"
	"os"
)

// peerUID fallback for non-Linux development environments.
// Linux uses SO_PEERCRED for connection-scoped UID extraction.
func peerUID(_ net.Conn) (int, error) {
	return os.Getuid(), nil
}
