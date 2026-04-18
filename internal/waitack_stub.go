//go:build !linux

package lumine

import (
	"net"
	"time"
)

func waitForAck(_ bool, _ net.Conn, delay time.Duration) error {
	time.Sleep(delay)
	return nil
}