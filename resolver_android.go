//go:build arm64 && android
// +build arm64,android

package main

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	dns1 = "8.8.8.8:53"
	dns2 = "1.1.1.1:53"
)

func init() {
	if runtime.GOOS == "android" || os.Getenv("ANDROID_ROOT") != "" || os.Getenv("ANDROID_DATA") != "" || strings.Contains(os.Getenv("PATH"), "/system/bin") {
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
		os.Setenv("GODEBUG", "netdns=go")
	}
}
