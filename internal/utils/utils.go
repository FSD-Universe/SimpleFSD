// Package utils
package utils

import (
	"fmt"
	"unicode"
)

func FormatCid(cid int) string {
	return fmt.Sprintf("%04d", cid)
}

func ContainsChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}
