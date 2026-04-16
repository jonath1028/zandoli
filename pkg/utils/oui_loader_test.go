// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldSkipActiveScan_BlockedMAC(t *testing.T) {
	// Test avec un MAC dans la blocklist
	blocked := ShouldSkipActiveScan("C8:D3:A3:AB:CD:EF")
	assert.True(t, blocked)
}

func TestShouldSkipActiveScan_NotBlockedMAC(t *testing.T) {
	// Test avec un MAC pas dans la blocklist
	blocked := ShouldSkipActiveScan("00:11:22:AB:CD:EF")
	assert.False(t, blocked)
}

func TestShouldSkipActiveScan_ShortMAC(t *testing.T) {
	// Test avec un MAC trop court
	blocked := ShouldSkipActiveScan("C8:D3")
	assert.False(t, blocked)
}

func TestShouldSkipActiveScan_EmptyMAC(t *testing.T) {
	// Test avec un MAC vide
	blocked := ShouldSkipActiveScan("")
	assert.False(t, blocked)
}

func TestShouldSkipActiveScan_WithColons(t *testing.T) {
	// Test avec des deux-points
	blocked1 := ShouldSkipActiveScan("C8:D3:A3:AB:CD:EF")
	blocked2 := ShouldSkipActiveScan("C8D3A3ABCDEF")
	// Les deux devraient donner le même résultat
	assert.Equal(t, blocked1, blocked2)
}
