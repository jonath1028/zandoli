package meta

import (
	"bytes"
	"encoding/binary"
)

// extractSMBHostname tente d’extraire une chaîne Unicode plausible (SMB1)

// bytesToUTF16 convertit une slice []byte en slice []uint16 (UCS2)
func bytesToUTF16(b []byte) []uint16 {
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(b)-1; i += 2 {
		u[i/2] = binary.LittleEndian.Uint16(b[i : i+2])
	}
	return u
}

// decodeUTF16 décode une slice UCS2 en string UTF-8
func decodeUTF16(utf16 []uint16) string {
	var buf bytes.Buffer
	for _, r := range utf16 {
		if r == 0 {
			break
		}
		buf.WriteRune(rune(r))
	}
	return buf.String()
}

// isValidSMBName applique des heuristiques simples (longueur, printable, etc.)
