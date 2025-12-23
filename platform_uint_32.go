//go:build (arm || 386) && linux
// +build linux
// +build arm 386

package main

func toUint(n int) uint32 {
	return uint32(n)
}