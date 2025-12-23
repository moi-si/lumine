//go:build (amd64 || arm64) && linux
// +build linux
// +build amd64 arm64

package main

func toUint(n int) uint64 {
	return uint64(n)
}