//go:build darwin

package main

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func sendOOB(conn net.Conn) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return fmt.Errorf("get raw conn: %w", err)
	}

	var fd uintptr
	if ctrlErr := rawConn.Control(func(f uintptr) {
		fd = f
	}); ctrlErr != nil {
		return fmt.Errorf("control: %w", ctrlErr)
	}
	if fd == 0 {
		return fmt.Errorf("invalid socket descriptor")
	}
	if err = unix.Sendto(int(fd), []byte{'&'}, unix.MSG_OOB, nil); err != nil {
		return fmt.Errorf("unix.Sendto (MSG_OOB): %w", err)
	}
	return nil
}

func minReachableTTL(string, bool, int, int, time.Duration) (int, bool, error) {
	return -1, false, errors.ErrUnsupported
}

func desyncSend(net.Conn, bool, []byte, int, int, int, time.Duration) error {
	return errors.ErrUnsupported
}
