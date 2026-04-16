// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"testing"
	"time"

	"zandoli/internal/logger"
	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// Test_IGMPv2_Query_NoPanic teste la gestion d'un paquet IGMPv2 Query sans panic
func Test_IGMPv2_Query_NoPanic(t *testing.T) {
	// Créer un logger pour le test
	log, _ := logger.New("test", nil)

	// Créer un aggregator pour les tests
	agg := NewAggregator()
	agg.SetLogger(log)

	// Créer un dispatcher
	dispatcher := NewDispatcherSimple(log, agg)

	// Construire un paquet IPv4 + IGMPv2 Query vers 224.0.0.1 depuis 192.168.2.1
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("01:00:5e:00:00:01") // Multicast MAC pour 224.0.0.1
	srcIP := net.ParseIP("192.168.2.1")
	dstIP := net.ParseIP("224.0.0.1")

	// Créer les couches du paquet
	ethernet := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
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
	// Type 0x11 (Membership Query), Max Response Time 0x64, Checksum 0, Group Address 0.0.0.0
	igmpPayload := []byte{
		0x11,       // Type: Membership Query
		0x64,       // Max Response Time (100 * 100ms = 10s)
		0x00, 0x00, // Checksum (sera calculé)
		0x00, 0x00, 0x00, 0x00, // Group Address: 0.0.0.0
	}

	// Serialiser le paquet sans la couche IGMP (car elle n'est pas sérialisable)
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

	// Vérifier qu'il n'y a pas de panic
	assert.NotPanics(t, func() {
		dispatcher.Dispatch(pkt)
	})

	// Attendre un peu pour que le processing se termine
	time.Sleep(10 * time.Millisecond)

	// Vérifier que l'aggregator a bien reçu le protocole IGMP
	hosts := agg.GetAll()
	assert.Len(t, hosts, 1, "Devrait avoir exactement 1 hôte")

	host := hosts[0]
	assert.Contains(t, host.Protocols, "IGMP", "L'hôte devrait avoir le protocole IGMP")
	assert.Equal(t, srcIP.String(), host.IP.String(), "L'IP devrait correspondre à la source")
	// Note: Strength est un champ du ParsedRecord, pas du Host final
}

// Test_IGMPv3_Report_NoPanic teste la gestion d'un paquet IGMPv3 Report sans panic
func Test_IGMPv3_Report_NoPanic(t *testing.T) {
	// Créer un logger pour le test
	log, _ := logger.New("test", nil)

	// Créer un aggregator pour les tests
	agg := NewAggregator()
	agg.SetLogger(log)

	// Créer un dispatcher
	dispatcher := NewDispatcherSimple(log, agg)

	// Construire un paquet IPv4 + IGMPv3 Report avec 1 groupe (239.1.1.1)
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:66")
	dstMAC, _ := net.ParseMAC("01:00:5e:01:01:01") // Multicast MAC pour 239.1.1.1
	srcIP := net.ParseIP("192.168.2.2")
	dstIP := net.ParseIP("224.0.0.22") // IGMPv3 Reports vont vers 224.0.0.22

	// Créer les couches du paquet
	ethernet := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
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
	// Type 0x22 (IGMPv3 Membership Report), Checksum 0, Reserved 0, Number of Group Records 1
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

	// Vérifier qu'il n'y a pas de panic
	assert.NotPanics(t, func() {
		dispatcher.Dispatch(pkt)
	})

	// Attendre un peu pour que le processing se termine
	time.Sleep(10 * time.Millisecond)

	// Vérifier que l'aggregator a bien reçu le protocole IGMP
	hosts := agg.GetAll()
	assert.Len(t, hosts, 1, "Devrait avoir exactement 1 hôte")

	host := hosts[0]
	assert.Contains(t, host.Protocols, "IGMP", "L'hôte devrait avoir le protocole IGMP")
	assert.Equal(t, srcIP.String(), host.IP.String(), "L'IP devrait correspondre à la source")
	// Note: Strength est un champ du ParsedRecord, pas du Host final
}

// Test_IGMP_UnknownLayer_Graceful teste la gestion gracieuse d'un type de couche IGMP inconnu
func Test_IGMP_UnknownLayer_Graceful(t *testing.T) {
	// Créer un logger pour le test
	log, _ := logger.New("test", nil)

	// Créer un aggregator pour les tests
	agg := NewAggregator()
	agg.SetLogger(log)

	// Créer un dispatcher
	dispatcher := NewDispatcherSimple(log, agg)

	// Construire un paquet IPv4 avec un type IGMP inconnu
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:77")
	dstMAC, _ := net.ParseMAC("01:00:5e:00:00:01")
	srcIP := net.ParseIP("192.168.2.3")
	dstIP := net.ParseIP("224.0.0.1")

	// Créer les couches du paquet
	ethernet := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
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

	// IGMP avec un type inconnu (0xFF)
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

	// Vérifier qu'il n'y a pas de panic même avec un type inconnu
	assert.NotPanics(t, func() {
		dispatcher.Dispatch(pkt)
	})

	// Attendre un peu pour que le processing se termine
	time.Sleep(10 * time.Millisecond)

	// Vérifier que l'aggregator a bien reçu le protocole IGMP même avec un type inconnu
	hosts := agg.GetAll()
	// Note: Avec un type IGMP inconnu, le parser peut ne pas créer d'hôte, ce qui est acceptable
	// L'important est qu'il n'y ait pas de panic
	if len(hosts) > 0 {
		host := hosts[0]
		assert.Contains(t, host.Protocols, "IGMP", "L'hôte devrait avoir le protocole IGMP même avec un type inconnu")
		assert.Equal(t, srcIP.String(), host.IP.String(), "L'IP devrait correspondre à la source")
		// Note: Strength est un champ du ParsedRecord, pas du Host final
	}
}

// Test_ParseIGMPPacket_Direct teste directement la fonction ParseIGMPPacket
func Test_ParseIGMPPacket_Direct(t *testing.T) {
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

	// Tester directement ParseIGMPPacket
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
