//go:build (arm || 386) && linux

package lumine

import "golang.org/x/sys/unix"

func splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (int64, error) {
	n, err := unix.Splice(rfd, roff, wfd, woff, len, flags)
	return int64(n), err
}

func toUint(n int) uint32 {
	return uint32(n)
}
