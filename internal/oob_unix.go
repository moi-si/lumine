//go:build unix

package lumine

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
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

	toSend := make([]byte, len(data)+1)
	copy(toSend, data)
	toSend[len(data)] = oob

	if err = unix.Send(int(fd), toSend, unix.MSG_OOB); err != nil {
		return wrap("unix.Send (MSG_OOB)", err)
	}
	return nil
}
