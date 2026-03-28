//go:build !windows && !linux

package lumine

import (
	"errors"
	"net"
	"time"
)

var errTTLDNotSupported = errors.New("`ttl-d` is not supported on current system")

func minReachableTTL(string, bool, int, int, time.Duration) (int, bool, error) {
	return -1, false, errTTLDNotSupported
}

func desyncSend(net.Conn, bool, []byte, int, int, int, time.Duration) error {
	return errTTLDNotSupported
}
