//go:build windows || linux

package main

import (
	"sync"
	"time"
)

const minInterval = 100 * time.Millisecond

var (
	ttlCacheEnabled bool
	ttlCache        sync.Map
	ttlCacheTTL     int
)

type ttlCacheEntry struct {
	TTL      int
	ExpireAt time.Time
}
