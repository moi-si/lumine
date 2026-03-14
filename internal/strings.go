package lumine

import (
	"fmt"
	_ "strings"
)

func byteToStirng(b byte) string {
	return fmt.Sprintf("%x", b)
}

/*func joinString(values ...any) string {
	var builder strings.Builder
	for _, v := range values {
		switch val := v.(type) {
		case fmt.Stringer:
			builder.WriteString(val.String())
		case string:
			builder.WriteString(val)
		case error:
			builder.WriteString(val.Error())
		default:
			panic("unknown type")
		}
	}
	return builder.String()
}*/
