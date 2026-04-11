//go:build (arm || 386) && linux

package lumine

func itou(n int) uint32 {
	return uint32(n)
}
