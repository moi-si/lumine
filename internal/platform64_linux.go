//go:build (amd64 || arm64) && linux

package lumine

import "golang.org/x/sys/unix"

var splice = unix.Splice

func toUint(n int) uint64 {
	return uint64(n)
}
