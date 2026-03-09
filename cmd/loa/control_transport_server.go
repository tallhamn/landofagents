package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/marcusmom/land-of-agents/app/adapters/openclaw"
	"github.com/marcusmom/land-of-agents/engine/services/loaauthority"
	"github.com/marcusmom/land-of-agents/engine/worker"
)

func serveControl(socketPath string) error {
	auth, err := loaauthority.New(kitDir(), worker.WithLaunchValidator(openclaw.StrictValidator{}))
	if err != nil {
		return err
	}
	return serveControlWithAuthority(socketPath, auth)
}

func serveControlWithAuthority(socketPath string, auth controlAuthority) error {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return fmt.Errorf("socket path is required")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0755); err != nil {
		return err
	}
	if st, err := os.Stat(socketPath); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to overwrite non-socket path: %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0600); err != nil {
		return err
	}

	srv := newControlHTTPServer(auth)
	fmt.Printf("LOA control server listening on unix://%s\n", socketPath)
	return srv.Serve(ln)
}

func newControlHTTPServer(auth controlAuthority) *http.Server {
	mux := http.NewServeMux()
	registerControlRoutes(mux, auth)
	return &http.Server{
		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uid, err := peerUID(c)
			if err != nil {
				return context.WithValue(ctx, controlPeerErrKey{}, err)
			}
			return context.WithValue(ctx, controlPeerUIDKey{}, uid)
		},
	}
}

func registerControlRoutes(mux *http.ServeMux, auth controlAuthority) {
	mux.HandleFunc("/v1/spawn", makeSpawnHandler(auth))
	mux.HandleFunc("/v1/status", makeStatusHandler(auth))
	mux.HandleFunc("/v1/terminate", makeTerminateHandler(auth))
	mux.HandleFunc("/v1/list", makeListHandler(auth))
}
