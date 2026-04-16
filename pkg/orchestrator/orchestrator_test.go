// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package orchestrator

import (
	"net"
	"testing"
)

func mustMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

func TestMustMAC_Helper(t *testing.T) {
	m := mustMAC("aa:bb:cc:dd:ee:ff")
	if m.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected MAC: %s", m)
	}
}

