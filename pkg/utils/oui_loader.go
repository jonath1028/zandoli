// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"strings"
)

// macOUIBlocklist contains MAC OUIs to exclude from active scanning
// (printers, TVs, IoT devices that could crash or react badly to scanning)
var macOUIBlocklist = map[string]struct{}{
	"C8D3A3": {}, "84B802": {}, "C40415": {}, "00090F": {}, "F4CE46": {},
	"60152B": {}, "400025": {}, "000585": {}, "00301A": {}, "001B21": {},
	"C025E9": {}, "8C8590": {}, "AC6462": {}, "788A20": {}, "FCEcDA": {},
	"F09FC2": {}, "BCD767": {}, "80FA5B": {}, "44D9E7": {}, "C4AD34": {},
	"D807B6": {}, "50EC50": {}, "001F29": {}, "00170C": {},
}

// ShouldSkipActiveScan returns true if the MAC matches an OUI that should be excluded from active scanning.
// Used to avoid scanning fragile devices (printers, IoT, etc.)
func ShouldSkipActiveScan(mac string) bool {
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(mac) < 6 {
		return false
	}
	_, blocked := macOUIBlocklist[mac[:6]]
	return blocked
}
