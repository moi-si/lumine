//go:build darwin

package main

import (
	"errors"
	"net"
	"sync"
	"time"
)

var errUnsupported = errors.New("not supported yet")

var (
	ttlCacheEnabled bool
	ttlCache        sync.Map
	ttlCacheTTL     int
)

func sendOOB(net.Conn) error {
	return errUnsupported
}

func minReachableTTL(string, bool, int, int, time.Duration) (int, error) {
	return -1, errUnsupported
}

func desyncSend(net.Conn, bool, []byte, int, int, int, time.Duration) error {
	return errUnsupported
}