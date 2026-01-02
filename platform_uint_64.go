//go:build (amd64 || arm64) && linux
// +build amd64 arm64
// +build linux

package main

func toUint(n int) uint64 {
	return uint64(n)
}
