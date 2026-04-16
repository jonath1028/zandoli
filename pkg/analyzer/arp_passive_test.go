// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"net"
	"testing"
	"time"

	"zandoli/pkg/model"
	"zandoli/pkg/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseARPPacket_ARPReply(t *testing.T) {
	// Créer un paquet ARP Reply synthétique
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("ff:ee:dd:cc:bb:aa")
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.1")

	// Construire le paquet ARP
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         2, // ARP Reply
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}

	// Construire la trame Ethernet
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Sérialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		t.Fatalf("Erreur lors de la sérialisation: %v", err)
	}

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now().UTC(),
	}

	// Tester le parseur
	record := ParseARPPacket(pkt)
	if record == nil {
		t.Fatal("ParseARPPacket a retourné nil pour un ARP Reply valide")
	}

	// Vérifier les champs
	if record.MAC.String() != srcMAC.String() {
		t.Errorf("MAC attendue %v, obtenue %v", srcMAC, record.MAC)
	}

	if !record.IP.Equal(srcIP) {
		t.Errorf("IP attendue %v, obtenue %v", srcIP, record.IP)
	}

	if len(record.Protocols) != 1 || record.Protocols[0] != "ARP" {
		t.Errorf("Protocols attendu [ARP], obtenu %v", record.Protocols)
	}

	if record.Role != "" {
		t.Errorf("Role attendu vide, obtenu %s", record.Role)
	}

	if !record.OnlyARP {
		t.Error("OnlyARP devrait être true")
	}

	if record.Source != "passive" {
		t.Errorf("Source attendue 'passive', obtenue %s", record.Source)
	}
}

func TestParseARPPacket_GratuitousARP(t *testing.T) {
	// Créer un paquet Gratuitous ARP synthétique
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff") // Broadcast
	srcIP := net.ParseIP("192.168.1.100")

	// Construire le paquet ARP (Gratuitous ARP: sender = target)
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, // ARP Request
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(srcIP.To4()), // Même IP que source (Gratuitous)
	}

	// Construire la trame Ethernet
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Sérialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		t.Fatalf("Erreur lors de la sérialisation: %v", err)
	}

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now().UTC(),
	}

	// Tester le parseur
	record := ParseARPPacket(pkt)
	if record == nil {
		t.Fatal("ParseARPPacket a retourné nil pour un Gratuitous ARP valide")
	}

	// Vérifier les champs
	if record.MAC.String() != srcMAC.String() {
		t.Errorf("MAC attendue %v, obtenue %v", srcMAC, record.MAC)
	}

	if !record.IP.Equal(srcIP) {
		t.Errorf("IP attendue %v, obtenue %v", srcIP, record.IP)
	}

	if len(record.Protocols) != 1 || record.Protocols[0] != "ARP" {
		t.Errorf("Protocols attendu [ARP], obtenu %v", record.Protocols)
	}
}

func TestParseARPPacket_InvalidPacket(t *testing.T) {
	// Test avec un paquet non-ARP
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("ff:ee:dd:cc:bb:aa")

	// Construire une trame Ethernet avec EtherType non-ARP
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4, // Pas ARP
	}

	// Sérialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth)
	if err != nil {
		t.Fatalf("Erreur lors de la sérialisation: %v", err)
	}

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now().UTC(),
	}

	// Tester le parseur
	record := ParseARPPacket(pkt)
	if record != nil {
		t.Error("ParseARPPacket devrait retourner nil pour un paquet non-ARP")
	}
}

func TestParseARPPacket_ValidARPRequest(t *testing.T) {
	// Test avec un ARP Request normal (maintenant accepté)
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("ff:ee:dd:cc:bb:aa")
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.1")

	// Construire le paquet ARP (Request normal)
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, // ARP Request
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()), // IP différente (pas Gratuitous)
	}

	// Construire la trame Ethernet
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Sérialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		t.Fatalf("Erreur lors de la sérialisation: %v", err)
	}

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now().UTC(),
	}

	// Tester le parseur avec détection de type
	detector := NewARPAnomalyDetector()
	record := ParseARPPacketWithAnomalyDetectionAndType(pkt, detector)
	if record == nil {
		t.Error("ParseARPPacketWithAnomalyDetectionAndType devrait retourner un record pour un ARP Request valide")
	}

	// Vérifier que c'est bien un ARP Request
	if record.Info != "ARP Request" {
		t.Errorf("Info attendue 'ARP Request', obtenue %s", record.Info)
	}
}

func TestParseARPPacket_IntegrationWithAggregator(t *testing.T) {
	// Test d'intégration avec l'aggregator
	agg := NewAggregator()

	// Créer un paquet ARP Reply
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("ff:ee:dd:cc:bb:aa")
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.1")

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         2, // ARP Reply
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		t.Fatalf("Erreur lors de la sérialisation: %v", err)
	}

	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now().UTC(),
	}

	// Parser et agréger
	record := ParseARPPacket(pkt)
	if record == nil {
		t.Fatal("ParseARPPacket a retourné nil")
	}

	agg.Merge(record)

	// Vérifier que l'host a été créé avec la bonne IP
	hosts := agg.GetAll()
	if len(hosts) != 1 {
		t.Fatalf("Attendu 1 host, obtenu %d", len(hosts))
	}

	host := hosts[0]
	if host.MAC.String() != srcMAC.String() {
		t.Errorf("MAC attendue %v, obtenue %v", srcMAC, host.MAC)
	}

	if !host.IP.Equal(srcIP) {
		t.Errorf("IP attendue %v, obtenue %v", srcIP, host.IP)
	}

	if len(host.Protocols) != 1 || host.Protocols[0] != "ARP" {
		t.Errorf("Protocols attendu [ARP], obtenu %v", host.Protocols)
	}

	if !host.OnlyARP {
		t.Error("OnlyARP devrait être true")
	}
}

func TestParseARPPacket_ARPRequest(t *testing.T) {
	// Créer un paquet ARP Request synthétique
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff") // Broadcast
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.1")

	// Construire le paquet ARP
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         1, // ARP Request
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}

	// Construire la trame Ethernet
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Sérialiser le paquet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		t.Fatalf("Erreur lors de la sérialisation: %v", err)
	}

	// Créer le PacketEvent
	pkt := model.PacketEvent{
		SrcMAC:    srcMAC,
		Payload:   buf.Bytes(),
		Timestamp: time.Now().UTC(),
	}

	// Tester le parseur
	record := ParseARPPacket(pkt)
	if record == nil {
		t.Fatal("ParseARPPacket a retourné nil pour un ARP Request valide")
	}

	// Vérifier les champs
	if record.MAC.String() != srcMAC.String() {
		t.Errorf("MAC attendue %v, obtenue %v", srcMAC, record.MAC)
	}

	if !record.IP.Equal(srcIP) {
		t.Errorf("IP attendue %v, obtenue %v", srcIP, record.IP)
	}

	if len(record.Protocols) != 1 || record.Protocols[0] != "ARP" {
		t.Errorf("Protocols attendu [ARP], obtenu %v", record.Protocols)
	}

	if !record.OnlyARP {
		t.Error("OnlyARP devrait être true")
	}
}

func TestARPAnomalyDetector_HighRate(t *testing.T) {
	detector := NewARPAnomalyDetector()

	// Créer un record de test
	record := &ParsedRecord{
		MAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"ARP"},
		Info:      "ARP Request",
		Anomalies: []string{},
		OnlyARP:   true,
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Simuler un taux élevé de paquets dans une fenêtre d'une seconde
	baseTime := time.Now().UTC()
	anomalyDetected := false
	for i := 0; i < 15; i++ { // Plus que le seuil de 10
		// Espacer les paquets sur 500ms pour qu'ils soient dans la même seconde
		timestamp := baseTime.Add(time.Duration(i*50) * time.Millisecond)
		anomalies := detector.DetectAnomalies(record, timestamp)
		if utils.ContainsString(anomalies, "high_rate_per_src") {
			anomalyDetected = true
		}
	}

	if !anomalyDetected {
		t.Error("high_rate_per_src devrait être détecté")
	}
}

func TestARPAnomalyDetector_IPMacConflict(t *testing.T) {
	detector := NewARPAnomalyDetector()

	// Premier record
	record1 := &ParsedRecord{
		MAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		IP:        net.ParseIP("192.168.1.100"),
		Protocols: []string{"ARP"},
		Info:      "ARP Request",
		Anomalies: []string{},
		OnlyARP:   true,
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Deuxième record avec même IP mais MAC différente
	record2 := &ParsedRecord{
		MAC:       []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa},
		IP:        net.ParseIP("192.168.1.100"), // Même IP
		Protocols: []string{"ARP"},
		Info:      "ARP Request",
		Anomalies: []string{},
		OnlyARP:   true,
		Source:    "passive",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}

	// Premier paquet - pas d'anomalie
	anomalies1 := detector.DetectAnomalies(record1, time.Now().UTC())
	if utils.ContainsString(anomalies1, "ip_mac_conflict") {
		t.Error("ip_mac_conflict ne devrait pas être détecté pour le premier paquet")
	}

	// Deuxième paquet - anomalie détectée
	anomalies2 := detector.DetectAnomalies(record2, time.Now().UTC())
	if !utils.ContainsString(anomalies2, "ip_mac_conflict") {
		t.Error("ip_mac_conflict devrait être détecté pour le deuxième paquet")
	}
}
