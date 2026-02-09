//go:build windows || linux

package main

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

const minInterval = 100 * time.Millisecond

var (
	ttlCacheEnabled bool
	ttlCache        sync.Map
	ttlCacheTTL     int
)

type ttlCacheEntry struct {
	TTL      int
	ExpireAt time.Time
}

func getRawConn(conn net.Conn) (syscall.RawConn, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("not *net.TCPConn")
	}
	return tcpConn.SyscallConn()
}
