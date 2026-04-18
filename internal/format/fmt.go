package format

import (
	"fmt"
	"strconv"
	"strings"
)

func Byte(b byte) string {
	var hexBuf [2]byte
	const hexDigits = "0123456789abcdef"
	hexBuf[0] = hexDigits[b>>4]
	hexBuf[1] = hexDigits[b&0x0f]
	return string(hexBuf[:])
}

func Concat(values ...any) string {
	var builder strings.Builder
	for _, v := range values {
		switch val := v.(type) {
		case fmt.Stringer:
			builder.WriteString(val.String())
		case string:
			builder.WriteString(val)
		case error:
			builder.WriteString(val.Error())
		case int:
			builder.WriteString(strconv.Itoa(val))
		case int8:
			builder.WriteString(Int(val))
		case int16:
			builder.WriteString(Int(val))
		case int32:
			builder.WriteString(Int(val))
		case int64:
			builder.WriteString(Int(val))
		case uint:
			builder.WriteString(Uint(val))
		case uint8:
			builder.WriteString(Uint(val))
		case uint16:
			builder.WriteString(Uint(val))
		case uint32:
			builder.WriteString(Uint(val))
		case uint64:
			builder.WriteString(Uint(val))
		default:
			panic("unsupported type")
		}
	}
	return builder.String()
}

func Int[T int | int8 | int16 | int32 | int64](v T) string {
	return strconv.FormatInt(int64(v), 10)
}

func Uint[T uint | uint8 | uint16 | uint32 | uint64](v T) string {
	return strconv.FormatUint(uint64(v), 10)
}
