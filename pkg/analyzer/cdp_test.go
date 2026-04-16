// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseCDPFromPayload(t *testing.T) {
	tests := []struct {
		name             string
		payload          []byte
		expectedResult   bool
		expectedDeviceID string
		expectedRole     string
	}{
		{
			name: "valid CDP packet with basic TLVs",
			payload: createTestCDPPayload(t, map[uint16][]byte{
				0x01: []byte("R1"),                // Device ID
				0x03: []byte("Ethernet0"),         // Port ID
				0x06: []byte("cisco 1601"),        // Platform
				0x04: createCapabilitiesTLV(0x01), // Router capability
			}),
			expectedResult:   true,
			expectedDeviceID: "R1",
			expectedRole:     "reseau",
		},
		{
			name:           "empty payload",
			payload:        []byte{},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
			timestamp := time.Now()

			result, err := parseCDPFromPayload(tt.payload, srcMAC, timestamp)

			if !tt.expectedResult {
				assert.Nil(t, result, "Expected nil result for invalid payload")
				return
			}

			assert.NoError(t, err, "Should not return error for valid CDP")
			assert.NotNil(t, result, "Should return a valid ParsedRecord")
			assert.Equal(t, srcMAC, result.MAC, "MAC should match")
			assert.Contains(t, result.Protocols, "CDP", "Should contain CDP protocol")

			if tt.expectedDeviceID != "" {
				assert.NotNil(t, result.CDP, "CDP info should be present")
				assert.Equal(t, tt.expectedDeviceID, result.CDP.DeviceID, "Device ID should match")
			}

			if tt.expectedRole != "" {
				assert.Equal(t, tt.expectedRole, result.Role, "Role should match")
			}
		})
	}
}

func TestDetermineRoleFromCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		capabilities uint32
		expectedRole string
	}{
		{"Router capability", 0x01, "reseau"},
		{"Switch capability", 0x08, "reseau"},
		{"AP capability", 0x80, "reseau"},
		{"Host capability", 0x10, "client"},
		{"Unknown capability", 0x200, "reseau"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := determineRoleFromCapabilities(tt.capabilities)
			assert.Equal(t, tt.expectedRole, role)
		})
	}
}

// Helper functions
func createTestCDPPayload(t *testing.T, tlvs map[uint16][]byte) []byte {
	payload := []byte{0x02, 0xb4, 0x00, 0x00} // CDP header

	for tlvType, tlvValue := range tlvs {
		tlvLength := uint16(len(tlvValue) + 4)
		payload = append(payload, byte(tlvType>>8), byte(tlvType&0xff))
		payload = append(payload, byte(tlvLength>>8), byte(tlvLength&0xff))
		payload = append(payload, tlvValue...)
	}

	return payload
}

func createCapabilitiesTLV(capabilities uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, capabilities)
	return data
}
