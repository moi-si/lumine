//go:build unix

package lumine

import (
	"net"

	"golang.org/x/sys/unix"
)

func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	// Tested on Android; does not work as expected.
	rawConn, err := getRawConn(conn)
	if err != nil {
		return wrap("get raw conn", err)
	}

	toSend := make([]byte, len(data)+1)
	copy(toSend, data)
	toSend[len(data)] = oob

	var innerErr error
	err = rawConn.Write(func(fd uintptr) (done bool) {
		innerErr = unix.Send(int(fd), toSend, unix.MSG_OOB)
		return innerErr != unix.EAGAIN
	})

	if err != nil {
		return wrap("rawConn.Write", err)
	}
	if innerErr != nil {
		return wrap("unix.Send (MSG_OOB)", innerErr)
	}
	return nil
}
