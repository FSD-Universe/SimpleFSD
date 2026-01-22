// Package command
package command

import (
	"slices"
	"strings"
)

const (
	CallsignMinLen = 3
	CallsignMaxLen = 12
	ForbiddenChars = "!@#$%*:& \t"
)

var validSuffix = []string{"DEL", "GND", "RMP", "TWR", "APP", "CTR", "FSS", "ATIS"}

func isValidAtc(callsign string) bool {
	if !callsignValid(callsign) {
		return false
	}
	d := strings.Split(callsign, "_")
	if len(d) == 1 {
		return false
	}
	suffix := d[len(d)-1]
	return slices.Contains(validSuffix, suffix)
}

func callsignValid(callsign string) bool {
	if len(callsign) < CallsignMinLen || len(callsign) >= CallsignMaxLen {
		return false
	}

	if strings.ContainsAny(callsign, ForbiddenChars) {
		return false
	}

	for _, r := range callsign {
		if r > 127 {
			return false
		}
	}

	return true
}
