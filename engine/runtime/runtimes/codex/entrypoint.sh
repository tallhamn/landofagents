#!/bin/sh
# Add host-mounted binaries to PATH if present
if [ -d /host/usr/bin ]; then
  export PATH="$PATH:/host/usr/bin"
  [ -d /host/usr/lib/go ] && export GOROOT=/host/usr/lib/go
fi
# Use host Go module cache if mounted
[ -d /home/node/go/pkg/mod ] && export GOPATH=/home/node/go
exec codex --full-auto
