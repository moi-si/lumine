package lumine

import (
	"net"

	E "github.com/moi-si/lumine/internal/errors"
	"golang.org/x/sys/windows"
)

func sendWithOOB(conn net.Conn, data []byte, oob byte) error {
	rawConn, err := getTCPRawConn(conn)
	if err != nil {
		return err
	}

	var toSend []byte
	if data == nil {
		toSend = []byte{oob}
	} else {
		toSend = make([]byte, len(data)+1)
		copy(toSend, data)
		toSend[len(data)] = oob
	}
	wsabuf := windows.WSABuf{
		Len: uint32(len(toSend)),
		Buf: &toSend[0],
	}
	var n uint32
	var innerErr error
	err = rawConn.Write(func(fd uintptr) (done bool) {
		innerErr = windows.WSASend(
			windows.Handle(fd),
			&wsabuf,
			1,
			&n,
			windows.MSG_OOB,
			nil,
			nil,
		)
		return true
	})
	if err != nil {
		return E.WithStr("raw write (wsasend)", err)
	}
	if innerErr != nil && innerErr != windows.NOERROR {
		return E.WithStr("wsasend (MSG_OOB)", innerErr)
	}
	return nil
}
