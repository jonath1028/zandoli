package utils

import (
	"bytes"
	"encoding/binary"
)

// BytesToUTF16 convertit une séquence UCS-2 LittleEndian vers []uint16
func BytesToUTF16(b []byte) []uint16 {
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(b)-1; i += 2 {
		u[i/2] = binary.LittleEndian.Uint16(b[i : i+2])
	}
	return u
}

// DecodeUTF16 décode une séquence []uint16 vers une string UTF-8
func DecodeUTF16(utf16 []uint16) string {
	var buf bytes.Buffer
	for _, r := range utf16 {
		if r == 0 {
			break
		}
		buf.WriteRune(rune(r))
	}
	return buf.String()
}
