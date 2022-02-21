package siwe

import "strings"

func isEmpty(str *string) bool {
	return str == nil || len(strings.TrimSpace(*str)) == 0
}
