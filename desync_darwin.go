//go:build darwin

package main

import (
	"errors"
	"net"
	"time"
)

func minReachableTTL(string, bool, int, int, time.Duration) (int, bool, error) {
	return -1, false, errors.ErrUnsupported
}

func desyncSend(net.Conn, bool, []byte, int, int, int, time.Duration) error {
	return errors.ErrUnsupported
}
