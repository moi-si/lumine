//go:build linux

package lumine

import (
	"net"
	"time"

	E "github.com/moi-si/lumine/internal/errors"
	"golang.org/x/sys/unix"
)

func waitForAck(enabled bool, conn net.Conn, delay time.Duration) error {
	if !enabled {
		time.Sleep(delay)
		return nil
	}
	rawConn, err := getTCPRawConn(conn)
	if err != nil {
		return err
	}
	var innerErr error
	rawCtrlErr := rawConn.Control(func(fd uintptr) {
		start := time.Now()
		fdInt := int(fd)
		for {
			var tcpInfo *unix.TCPInfo
			tcpInfo, innerErr = unix.GetsockoptTCPInfo(fdInt, unix.IPPROTO_TCP, unix.TCP_INFO)
			if innerErr != nil {
				return
			}
			if tcpInfo.Unacked == 0 {
				if time.Since(start) <= 20*time.Millisecond {
					time.Sleep(delay)
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	if rawCtrlErr != nil {
		return E.WithStr("wait for ACK: raw control", rawCtrlErr)
	} else if innerErr != nil {
		return E.WithStr("wait for ACK: get tcp info", innerErr)
	}
	return nil
}
