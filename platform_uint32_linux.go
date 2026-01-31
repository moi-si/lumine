//go:build (arm || 386) && linux

package main

func toUint(n int) uint32 {
	return uint32(n)
}
