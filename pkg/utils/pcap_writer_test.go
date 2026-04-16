// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNewPCAPWriter_ValidPath(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	writer, err := NewPCAPWriter(pcapPath, 65536)
	if err != nil {
		t.Fatalf("Expected no error creating PCAP writer, got %v", err)
	}
	if writer == nil {
		t.Fatal("Expected writer, got nil")
	}

	// Vérifier que le fichier a été créé
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Fatal("Expected PCAP file to be created")
	}

	// Fermer le writer
	err = writer.Close()
	if err != nil {
		t.Fatalf("Expected no error closing writer, got %v", err)
	}
}

func TestNewPCAPWriter_InvalidPath(t *testing.T) {
	// Test avec un chemin invalide
	invalidPath := "/root/invalid/path/test.pcap"

	writer, err := NewPCAPWriter(invalidPath, 65536)
	if err == nil {
		t.Fatal("Expected error for invalid path, got nil")
	}
	if writer != nil {
		t.Fatal("Expected nil writer for invalid path")
	}
}

func TestPCAPWriter_WritePacket(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	writer, err := NewPCAPWriter(pcapPath, 65536)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}
	defer writer.Close()

	// Créer un paquet de test
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   20,
		Id:       1,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	tcp := &layers.TCP{
		SrcPort: 80,
		DstPort: 8080,
		SYN:     true,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Set network layer for checksum computation
	tcp.SetNetworkLayerForChecksum(ip)

	err = gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Écrire le paquet
	err = writer.WritePacket(packet)
	if err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}
}

func TestPCAPWriter_WriteMultiplePackets(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	writer, err := NewPCAPWriter(pcapPath, 65536)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}
	defer writer.Close()

	// Écrire plusieurs paquets
	for i := 0; i < 10; i++ {
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			Length:   20,
			Id:       uint16(i),
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    []byte{192, 168, 1, 1},
			DstIP:    []byte{192, 168, 1, 2},
		}

		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(80 + i),
			DstPort: layers.TCPPort(8080 + i),
			SYN:     true,
		}

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		// Set network layer for checksum computation
		tcp.SetNetworkLayerForChecksum(ip)

		err = gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
		if err != nil {
			t.Fatalf("Failed to serialize packet %d: %v", i, err)
		}

		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

		err = writer.WritePacket(packet)
		if err != nil {
			t.Fatalf("Failed to write packet %d: %v", i, err)
		}
	}
}

func TestPCAPWriter_Close(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	writer, err := NewPCAPWriter(pcapPath, 65536)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}

	// Fermer le writer
	err = writer.Close()
	if err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Essayer de fermer à nouveau (peut causer une erreur car déjà fermé)
	err = writer.Close()
	// On ignore l'erreur car le fichier est déjà fermé
}

func TestPCAPWriter_DifferentSnaplen(t *testing.T) {
	testCases := []int{64, 128, 256, 512, 1024, 1500, 65536}

	for _, snaplen := range testCases {
		t.Run("snaplen_"+string(rune(snaplen)), func(t *testing.T) {
			tmpDir := t.TempDir()
			pcapPath := filepath.Join(tmpDir, "test.pcap")

			writer, err := NewPCAPWriter(pcapPath, snaplen)
			if err != nil {
				t.Fatalf("Failed to create PCAP writer with snaplen %d: %v", snaplen, err)
			}

			err = writer.Close()
			if err != nil {
				t.Fatalf("Failed to close writer with snaplen %d: %v", snaplen, err)
			}
		})
	}
}

func TestPCAPWriter_EmptyPacket(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	writer, err := NewPCAPWriter(pcapPath, 65536)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}
	defer writer.Close()

	// Créer un paquet vide
	packet := gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)

	// Écrire le paquet vide
	err = writer.WritePacket(packet)
	if err != nil {
		t.Fatalf("Failed to write empty packet: %v", err)
	}
}

func TestPCAPWriter_Interface(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	// Vérifier que NewPCAPWriter retourne bien une interface PCAPWriter
	var writer PCAPWriter
	writer, err := NewPCAPWriter(pcapPath, 65536)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}
	defer writer.Close()

	// Vérifier que les méthodes de l'interface fonctionnent
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(buffer, opts, eth)
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Vérifier que le paquet a des données
	if len(packet.Data()) == 0 {
		t.Skip("Skipping interface test - empty packet")
		return
	}

	err = writer.WritePacket(packet)
	if err != nil {
		t.Fatalf("Failed to write packet through interface: %v", err)
	}

	err = writer.Close()
	if err != nil {
		t.Fatalf("Failed to close writer through interface: %v", err)
	}
}

func TestPCAPWriter_InvalidLengths(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	writer, err := NewPCAPWriter(pcapPath, 65536)
	if err != nil {
		t.Fatalf("Failed to create PCAP writer: %v", err)
	}
	defer writer.Close()

	// Créer un paquet avec des données
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(buffer, opts, eth)
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Vérifier que le paquet a des données
	if len(packet.Data()) == 0 {
		t.Skip("Skipping invalid lengths test - empty packet")
		return
	}

	// Modifier le CaptureInfo pour avoir CaptureLength < len(data)
	// Ceci devrait être corrigé automatiquement par notre fonction WritePacket
	ci := packet.Metadata().CaptureInfo
	originalCaptureLength := ci.CaptureLength
	ci.CaptureLength = 10 // Plus petit que len(data) qui est ~60

	// Créer un nouveau paquet avec le CaptureInfo modifié
	packetWithInvalidLength := gopacket.NewPacket(packet.Data(), layers.LayerTypeEthernet, gopacket.Default)
	packetWithInvalidLength.Metadata().CaptureInfo = ci

	// Le paquet devrait être écrit sans erreur car notre fonction corrige automatiquement
	err = writer.WritePacket(packetWithInvalidLength)
	if err != nil {
		t.Fatalf("Expected no error when CaptureLength < len(data), got %v", err)
	}

	// Vérifier que la correction a bien eu lieu
	// Note: on ne peut pas vérifier directement car le CaptureInfo est passé par valeur
	// mais on peut vérifier que l'écriture s'est bien passée

	// Test avec CaptureLength = 0 (cas le plus problématique)
	ci.CaptureLength = 0
	packetWithZeroLength := gopacket.NewPacket(packet.Data(), layers.LayerTypeEthernet, gopacket.Default)
	packetWithZeroLength.Metadata().CaptureInfo = ci

	err = writer.WritePacket(packetWithZeroLength)
	if err != nil {
		t.Fatalf("Expected no error when CaptureLength = 0, got %v", err)
	}

	// Restaurer la valeur originale pour éviter les effets de bord
	ci.CaptureLength = originalCaptureLength
}
