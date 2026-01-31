//go:build godns

package main

import (
	"context"
	"net"
	"time"
)

const (
	dns1 = "8.8.8.8:53"
	dns2 = "1.1.1.1:53"
)

func init() {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 3 * time.Second}
			if conn, err := dialer.DialContext(ctx, "udp", dns1); err != nil {
				return conn, nil
			}
			return dialer.DialContext(ctx, "udp", dns2)
		},
	}
}
