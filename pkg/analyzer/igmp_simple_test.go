// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// Test_ParseIGMPPacket_NoPanic teste directement la fonction ParseIGMPPacket sans panic
func Test_ParseIGMPPacket_NoPanic(t *testing.T) {
	// Créer un paquet IGMPv2 Query
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:88")
	srcIP := net.ParseIP("192.168.2.4")
	dstIP := net.ParseIP("224.0.0.1")

	// Créer les couches du paquet
	ethernet := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// IGMPv2 Membership Query - construire manuellement le payload IGMP
	igmpPayload := []byte{
		0x11,       // Type: Membership Query
		0x64,       // Max Response Time
		0x00, 0x00, // Checksum (sera calculé)
		0x00, 0x00, 0x00, 0x00, // Group Address: 0.0.0.0
	}

	// Serialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ethernet,
		ipv4,
		gopacket.Payload(igmpPayload),
	)
	assert.NoError(t, err)

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now(),
		TTL:       64,
	}

	// Tester directement ParseIGMPPacket - vérifier qu'il n'y a pas de panic
	assert.NotPanics(t, func() {
		record, err := ParseIGMPPacket(pkt)

		// Vérifier que la fonction retourne un résultat valide
		assert.NoError(t, err, "ParseIGMPPacket ne devrait pas retourner d'erreur")
		assert.NotNil(t, record, "ParseIGMPPacket devrait retourner un record")

		if record != nil {
			assert.Contains(t, record.Protocols, "IGMP", "Le record devrait contenir le protocole IGMP")
			assert.Equal(t, srcIP.To4(), record.IP.To4(), "L'IP devrait correspondre à la source")
			assert.Equal(t, "client", record.Role, "Le rôle devrait être 'client'")
			assert.Equal(t, "low", record.Strength, "La force devrait être 'low'")
			assert.Contains(t, record.Info, "membership_query", "L'info devrait contenir le type IGMP")
		}
	})
}

// Test_ParseIGMPPacket_IGMPv3_NoPanic teste IGMPv3 Report sans panic
func Test_ParseIGMPPacket_IGMPv3_NoPanic(t *testing.T) {
	// Créer un paquet IGMPv3 Report
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:99")
	srcIP := net.ParseIP("192.168.2.5")
	dstIP := net.ParseIP("224.0.0.22")

	// Créer les couches du paquet
	ethernet := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x16},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// IGMPv3 Membership Report - construire manuellement le payload IGMP
	igmpPayload := []byte{
		0x22,       // Type: IGMPv3 Membership Report
		0x00,       // Reserved
		0x00, 0x00, // Checksum (sera calculé)
		0x00, 0x00, // Reserved
		0x00, 0x01, // Number of Group Records: 1
	}

	// Serialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ethernet,
		ipv4,
		gopacket.Payload(igmpPayload),
	)
	assert.NoError(t, err)

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now(),
		TTL:       64,
	}

	// Tester directement ParseIGMPPacket - vérifier qu'il n'y a pas de panic
	assert.NotPanics(t, func() {
		record, err := ParseIGMPPacket(pkt)

		// Vérifier que la fonction retourne un résultat valide
		assert.NoError(t, err, "ParseIGMPPacket ne devrait pas retourner d'erreur")
		assert.NotNil(t, record, "ParseIGMPPacket devrait retourner un record")

		if record != nil {
			assert.Contains(t, record.Protocols, "IGMP", "Le record devrait contenir le protocole IGMP")
			assert.Equal(t, srcIP.To4(), record.IP.To4(), "L'IP devrait correspondre à la source")
			assert.Equal(t, "client", record.Role, "Le rôle devrait être 'client'")
			assert.Equal(t, "low", record.Strength, "La force devrait être 'low'")
		}
	})
}

// Test_ParseIGMPPacket_UnknownType_Graceful teste la gestion gracieuse d'un type IGMP inconnu
func Test_ParseIGMPPacket_UnknownType_Graceful(t *testing.T) {
	// Créer un paquet IGMP avec type inconnu
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:AA")
	srcIP := net.ParseIP("192.168.2.6")
	dstIP := net.ParseIP("224.0.0.1")

	// Créer les couches du paquet
	ethernet := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// IGMP avec type inconnu (0xFF)
	igmpPayload := []byte{
		0xFF,       // Type inconnu
		0x00,       // Max Response Time
		0x00, 0x00, // Checksum (sera calculé)
		0x00, 0x00, 0x00, 0x00, // Group Address: 0.0.0.0
	}

	// Serialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ethernet,
		ipv4,
		gopacket.Payload(igmpPayload),
	)
	assert.NoError(t, err)

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now(),
		TTL:       64,
	}

	// Tester directement ParseIGMPPacket - vérifier qu'il n'y a pas de panic même avec un type inconnu
	assert.NotPanics(t, func() {
		record, err := ParseIGMPPacket(pkt)

		// Vérifier que la fonction retourne un résultat valide même avec un type inconnu
		assert.NoError(t, err, "ParseIGMPPacket ne devrait pas retourner d'erreur même avec un type inconnu")
		// Note: Avec un type IGMP inconnu, le parser peut retourner nil, ce qui est acceptable
		// L'important est qu'il n'y ait pas de panic
		if record != nil {
			assert.Contains(t, record.Protocols, "IGMP", "Le record devrait contenir le protocole IGMP même avec un type inconnu")
			assert.Equal(t, srcIP.To4(), record.IP.To4(), "L'IP devrait correspondre à la source")
			assert.Equal(t, "client", record.Role, "Le rôle devrait être 'client'")
			assert.Equal(t, "low", record.Strength, "La force devrait être 'low'")
		}
	})
}
