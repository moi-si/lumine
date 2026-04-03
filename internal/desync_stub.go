//go:build !windows && !linux

package lumine

import (
	"errors"
	"net"
	"time"

	"github.com/elastic/go-freelru"
	"golang.org/x/sync/singleflight"
)

var errTTLDNotSupported = errors.New("`ttl-d` is not supported on current system")

var (
	ttlCacheEnabled     bool
	ttlCache            *freelru.ShardedLRU[string, int]
	ttlCacheTTL         time.Duration
	ttlSingleflight     *singleflight.Group
)

func loadFakeTTLRules(string) error {
	return errTTLDNotSupported
}

func getMinimalReachableTTL(string, bool, int, int, time.Duration) (int, bool, error) {
	return -1, false, errTTLDNotSupported
}

func desyncSend(net.Conn, bool, []byte, int, int, int, time.Duration) error {
	return errTTLDNotSupported
}
