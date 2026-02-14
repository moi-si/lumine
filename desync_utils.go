package main

import (
	"time"

	"github.com/elastic/go-freelru"
)

var (
	ttlCacheEnabled bool
	ttlCache        *freelru.ShardedLRU[string, int]
	ttlCacheTTL     time.Duration
)
