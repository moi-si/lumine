//go:build (arm || 386) && linux
// +build arm 386
// +build linux

package main

func toUint(n int) uint32 {
	return uint32(n)
}
