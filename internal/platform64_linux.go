//go:build (amd64 || arm64) && linux

package lumine

func itou(n int) uint64 {
	return uint64(n)
}
