//go:build linux && (amd64 || arm64)

package lumine

import "golang.org/x/sys/unix"

func splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (int64, error) {
	return unix.Splice(rfd, roff, wfd, woff, len, flags)
}