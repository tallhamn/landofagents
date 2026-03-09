//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

func peerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("expected unix connection, got %T", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var innerErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e != nil {
			innerErr = e
			return
		}
		uid = int(ucred.Uid)
	}); err != nil {
		return -1, err
	}
	if innerErr != nil {
		return -1, innerErr
	}
	if uid < 0 {
		return -1, fmt.Errorf("peer uid unavailable")
	}
	return uid, nil
}
