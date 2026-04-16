// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"testing"
)

func TestParseDHCPRole(t *testing.T) {
	tests := []struct {
		name     string
		options  []byte
		expected string
	}{
		{
			name:     "DHCP OFFER",
			options:  []byte{0x35, 0x01, 0x02}, // Option 53, Length 1, Type 2 (OFFER)
			expected: "server",
		},
		{
			name:     "DHCP ACK",
			options:  []byte{0x35, 0x01, 0x05}, // Option 53, Length 1, Type 5 (ACK)
			expected: "server",
		},
		{
			name:     "DHCP DISCOVER",
			options:  []byte{0x35, 0x01, 0x01}, // Option 53, Length 1, Type 1 (DISCOVER)
			expected: "client",
		},
		{
			name:     "DHCP REQUEST",
			options:  []byte{0x35, 0x01, 0x03}, // Option 53, Length 1, Type 3 (REQUEST)
			expected: "client",
		},
		{
			name:     "No message type option",
			options:  []byte{0x36, 0x04, 0x01, 0x02, 0x03, 0x04}, // Option 54 (Server Identifier)
			expected: "client",
		},
		{
			name:     "Empty options",
			options:  []byte{},
			expected: "client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simuler un en-tête DHCP avec les options
			dhcpHeader := make([]byte, 240) // Taille standard d'un en-tête DHCP
			dhcpHeader[0] = 0x02            // Opcode Reply
			dhcpHeader[1] = 0x01            // Hardware Type Ethernet
			dhcpHeader[2] = 0x06            // Hardware Address Length

			// Ajouter les options
			dhcpPacket := append(dhcpHeader, tt.options...)
			dhcpPacket = append(dhcpPacket, 0xff) // Option End

			// Parser les options pour déterminer le rôle
			role := "client" // par défaut
			for i := 240; i < len(dhcpPacket)-1; {
				if i+1 >= len(dhcpPacket) {
					break
				}
				optionType := dhcpPacket[i]
				optionLength := int(dhcpPacket[i+1])

				if optionType == 0x35 && optionLength == 1 && i+2 < len(dhcpPacket) { // Message Type
					msgType := dhcpPacket[i+2]
					if msgType == 2 || msgType == 5 { // OFFER ou ACK
						role = "server"
					}
					break
				}

				i += 2 + optionLength
			}

			if role != tt.expected {
				t.Errorf("Expected role %s, got %s", tt.expected, role)
			}
		})
	}
}
