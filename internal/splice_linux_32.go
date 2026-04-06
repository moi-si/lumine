//go:build linux && (386 || arm)

package lumine

import "golang.org/x/sys/unix"

func splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (int64, error) {
	n, err := unix.Splice(rfd, roff, wfd, woff, len, flags)
	return int64(n), err
}