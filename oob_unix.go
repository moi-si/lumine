//go:build unix

package main

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func sendWithOOB(conn net.Conn, b []byte) error {
	rawConn, err := getRawConn(conn)
	if err != nil {
		return wrap("get raw conn", err)
	}

	var fd int
	if ctrlErr := rawConn.Control(func(f uintptr) {
		fd = int(f)
	}); ctrlErr != nil {
		return wrap("control", ctrlErr)
	}
	if fd == 0 {
		return errors.New("invalid socket descriptor")
	}

	data := make([]byte, len(b)+1)
	copy(data, b)
	data[len(b)] = '&'

	if err = unix.Send(int(fd), data, unix.MSG_OOB); err != nil {
		return wrap("unix.Send (MSG_OOB)", err)
	}
	return nil
}
