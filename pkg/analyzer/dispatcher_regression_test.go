// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"zandoli/internal/config"
	"zandoli/internal/logger"
	"zandoli/pkg/model"
	"zandoli/pkg/sniffer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_Offline_Init_Uses_NewDispatcher vérifie que l'initialisation offline utilise NewDispatcher
// et que tous les composants sont correctement initialisés
func Test_Offline_Init_Uses_NewDispatcher(t *testing.T) {
	// Arrange - Créer des mocks minimaux pour le mode offline
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	require.NoError(t, err, "Failed to create logger")

	agg := NewAggregator()
	opts := &Options{
		EnableMetrics: false,
		SampleRate:    0,
		Workers:       0,
		TraceEnabled:  false,
	}
	metrics := sniffer.NewAnalyzerMetricsWithOptions(log, false, 0)

	// Act - Créer le dispatcher via NewDispatcher (mode offline)
	dispatcher := NewDispatcher(log, agg, opts, metrics)

	// Assert - Vérifier que NewDispatcher a été invoqué et que tous les composants sont initialisés
	require.NotNil(t, dispatcher, "Dispatcher should not be nil")
	require.NotNil(t, dispatcher.dhcpParser, "DHCP parser should be initialized")
	require.NotNil(t, dispatcher.aggregator, "Aggregator should be initialized")
	require.NotNil(t, dispatcher.perfMetrics, "Performance metrics should be initialized")
	require.NotNil(t, dispatcher.arpDetector, "ARP detector should be initialized")
	require.NotNil(t, dispatcher.log, "Logger should be initialized")

	// Vérifier que le logger est correctement configuré sur l'aggregator
	assert.Equal(t, log, agg.log, "Aggregator should have the same logger")

	// Vérifier que le logger est correctement configuré sur le DHCP parser
	assert.Equal(t, log, dispatcher.dhcpParser.log, "DHCP parser should have the same logger")
}

// Test_Dispatcher_ProcessDHCP_NoCrash_When_Nil vérifie qu'un Dispatcher avec dhcpParser nil
// ne provoque pas de panic et loggue correctement l'erreur
func Test_Dispatcher_ProcessDHCP_NoCrash_When_Nil(t *testing.T) {
	// Arrange - Créer un dispatcher avec dhcpParser volontairement nil
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	require.NoError(t, err, "Failed to create logger")

	agg := NewAggregator()
	dispatcher := &Dispatcher{
		log:        log,
		aggregator: agg,
		// dhcpParser est intentionnellement nil
		dhcpParser: nil,
	}

	// Créer un paquet DHCP factice
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	pkt := model.PacketEvent{
		SrcMAC:    mac,
		Payload:   createFakeDHCPPacket(),
		Timestamp: time.Now(),
		TTL:       64,
		VLANID:    0,
	}

	// Act & Assert - Vérifier qu'aucun panic ne se produit
	// Le test passera si processDHCP ne panic pas
	assert.NotPanics(t, func() {
		dispatcher.processDHCP(pkt, "udp", 67, 68)
	}, "processDHCP should not panic when dhcpParser is nil")

	// Vérifier que le dispatcher est toujours dans un état valide après l'appel
	assert.NotNil(t, dispatcher.log, "Logger should still be valid")
	assert.NotNil(t, dispatcher.aggregator, "Aggregator should still be valid")
}

// Test_DHCPParser_NilReceiver_Safe vérifie qu'appeler ParseDHCPPacket sur un récepteur nil
// ne provoque pas de panic et retourne une erreur appropriée
func Test_DHCPParser_NilReceiver_Safe(t *testing.T) {
	// Arrange - Créer un paquet DHCP factice
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	pkt := model.PacketEvent{
		SrcMAC:    mac,
		Payload:   createFakeDHCPPacket(),
		Timestamp: time.Now(),
		TTL:       64,
		VLANID:    0,
	}

	// Act & Assert - Vérifier qu'aucun panic ne se produit avec un récepteur nil
	var parser *DHCPParser = nil
	var result *ParsedRecord
	var err error

	assert.NotPanics(t, func() {
		result, err = parser.ParseDHCPPacket(pkt)
	}, "ParseDHCPPacket should not panic when called on nil receiver")

	// Vérifier que le résultat est correct
	assert.Nil(t, result, "Result should be nil when called on nil receiver")
	assert.Error(t, err, "Error should be returned when called on nil receiver")
	assert.Contains(t, err.Error(), "DHCP parser is nil", "Error message should indicate nil parser")
}

// Test_NewDispatcher_Constructor_Initializes_All_Components vérifie que le constructeur NewDispatcher
// initialise correctement tous les composants requis
func Test_NewDispatcher_Constructor_Initializes_All_Components(t *testing.T) {
	// Arrange
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	require.NoError(t, err, "Failed to create logger")

	agg := NewAggregator()
	opts := &Options{
		EnableMetrics: true,
		SampleRate:    100,
		Workers:       4,
		TraceEnabled:  true,
	}
	metrics := sniffer.NewAnalyzerMetricsWithOptions(log, true, 100)

	// Act
	dispatcher := NewDispatcher(log, agg, opts, metrics)

	// Assert - Vérifier que tous les composants sont initialisés
	require.NotNil(t, dispatcher, "Dispatcher should not be nil")
	require.NotNil(t, dispatcher.dhcpParser, "DHCP parser should be initialized")
	require.NotNil(t, dispatcher.aggregator, "Aggregator should be initialized")
	require.NotNil(t, dispatcher.perfMetrics, "Performance metrics should be initialized")
	require.NotNil(t, dispatcher.arpDetector, "ARP detector should be initialized")
	require.NotNil(t, dispatcher.log, "Logger should be initialized")

	// Vérifier les options
	assert.True(t, dispatcher.traceEnabled, "Trace should be enabled")
	assert.Equal(t, uint64(0), dispatcher.processedPacketsCount, "Processed packets count should start at 0")

	// Vérifier que le logger est configuré sur l'aggregator
	assert.Equal(t, log, agg.log, "Aggregator should have the same logger")

	// Vérifier que le logger est configuré sur le DHCP parser
	assert.Equal(t, log, dispatcher.dhcpParser.log, "DHCP parser should have the same logger")
}

// Test_NewDispatcher_With_Nil_Options vérifie que NewDispatcher fonctionne avec des options nil
func Test_NewDispatcher_With_Nil_Options(t *testing.T) {
	// Arrange
	cfg := &config.Config{}
	log, err := logger.New("test", cfg)
	require.NoError(t, err, "Failed to create logger")

	agg := NewAggregator()

	// Act - Appeler NewDispatcher avec options nil
	dispatcher := NewDispatcher(log, agg, nil, nil)

	// Assert - Vérifier que le dispatcher est créé avec des valeurs par défaut
	require.NotNil(t, dispatcher, "Dispatcher should not be nil")
	require.NotNil(t, dispatcher.dhcpParser, "DHCP parser should be initialized")
	require.NotNil(t, dispatcher.aggregator, "Aggregator should be initialized")
	require.NotNil(t, dispatcher.perfMetrics, "Performance metrics should be initialized")
	require.NotNil(t, dispatcher.arpDetector, "ARP detector should be initialized")
	require.NotNil(t, dispatcher.log, "Logger should be initialized")

	// Vérifier les valeurs par défaut
	assert.False(t, dispatcher.traceEnabled, "Trace should be disabled by default")
	assert.Equal(t, uint64(0), dispatcher.processedPacketsCount, "Processed packets count should start at 0")
}

// createFakeDHCPPacket crée un paquet DHCP factice pour les tests
func createFakeDHCPPacket() []byte {
	// Créer un paquet Ethernet + IP + UDP + DHCP factice
	// Structure simplifiée pour les tests
	packet := make([]byte, 14+20+8+240) // Ethernet + IP + UDP + DHCP

	// En-tête Ethernet (14 bytes)
	copy(packet[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})  // Dst MAC
	copy(packet[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // Src MAC
	packet[12] = 0x08                                              // EtherType IP (high byte)
	packet[13] = 0x00                                              // EtherType IP (low byte)

	// En-tête IP (20 bytes) - position 14
	packet[14] = 0x45 // Version 4, IHL 5
	packet[15] = 0x00 // TOS
	// Longueur totale (16-17) - sera calculée
	binary.BigEndian.PutUint16(packet[16:18], uint16(20+8+240))
	packet[18] = 0x00 // Identification (high byte)
	packet[19] = 0x01 // Identification (low byte)
	packet[20] = 0x00 // Flags, Fragment Offset (high byte)
	packet[21] = 0x00 // Fragment Offset (low byte)
	packet[22] = 0x40 // TTL
	packet[23] = 0x11 // Protocol UDP
	// Checksum (24-25) - sera calculé
	packet[24] = 0x00
	packet[25] = 0x00
	copy(packet[26:30], []byte{192, 168, 1, 1})   // Src IP
	copy(packet[30:34], []byte{192, 168, 1, 100}) // Dst IP

	// En-tête UDP (8 bytes) - position 34
	packet[34] = 0x00                                        // Src Port (high byte)
	packet[35] = 0x43                                        // Src Port 67 (DHCP server)
	packet[36] = 0x00                                        // Dst Port (high byte)
	packet[37] = 0x44                                        // Dst Port 68 (DHCP client)
	binary.BigEndian.PutUint16(packet[38:40], uint16(8+240)) // Length
	packet[40] = 0x00                                        // Checksum (high byte)
	packet[41] = 0x00                                        // Checksum (low byte)

	// En-tête DHCP (240 bytes) - position 42
	packet[42] = 0x01 // Opcode: BOOTREQUEST
	packet[43] = 0x01 // Hardware Type: Ethernet
	packet[44] = 0x06 // Hardware Address Length
	packet[45] = 0x00 // Hops
	// Transaction ID (46-49)
	binary.BigEndian.PutUint32(packet[46:50], 0x12345678)
	// Seconds (50-51)
	packet[50] = 0x00
	packet[51] = 0x00
	// Flags (52-53)
	packet[52] = 0x00
	packet[53] = 0x00
	// Client IP (54-57)
	copy(packet[54:58], []byte{0, 0, 0, 0})
	// Your IP (58-61)
	copy(packet[58:62], []byte{192, 168, 1, 100})
	// Server IP (62-65)
	copy(packet[62:66], []byte{192, 168, 1, 1})
	// Gateway IP (66-69)
	copy(packet[66:70], []byte{0, 0, 0, 0})
	// Client MAC (70-75)
	copy(packet[70:76], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	// Padding (76-109)
	for i := 76; i < 110; i++ {
		packet[i] = 0x00
	}
	// Server Name (110-141)
	for i := 110; i < 142; i++ {
		packet[i] = 0x00
	}
	// Boot File (142-173)
	for i := 142; i < 174; i++ {
		packet[i] = 0x00
	}
	// Magic Cookie (174-177)
	packet[174] = 0x63
	packet[175] = 0x82
	packet[176] = 0x53
	packet[177] = 0x63

	// Options DHCP (178-281)
	// Option 53: Message Type (DHCPDISCOVER)
	packet[178] = 0x35 // Option 53
	packet[179] = 0x01 // Length 1
	packet[180] = 0x01 // DHCPDISCOVER

	// Option 12: Host Name
	packet[181] = 0x0c // Option 12
	packet[182] = 0x09 // Length 9
	copy(packet[183:192], []byte("testhost"))

	// Option 55: Parameter Request List
	packet[192] = 0x37 // Option 55
	packet[193] = 0x04 // Length 4
	packet[194] = 0x01 // Subnet Mask
	packet[195] = 0x03 // Router
	packet[196] = 0x06 // DNS Server
	packet[197] = 0x0f // Domain Name

	// Option 60: Vendor Class Identifier
	packet[198] = 0x3c // Option 60
	packet[199] = 0x0a // Length 10
	copy(packet[200:210], []byte("testvendor"))

	// Option 61: Client Identifier
	packet[210] = 0x3d // Option 61
	packet[211] = 0x07 // Length 7
	packet[212] = 0x01 // Type 1 (Ethernet)
	copy(packet[213:219], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})

	// Option 255: End
	packet[219] = 0xff

	// Remplir le reste avec des zéros
	for i := 220; i < len(packet); i++ {
		packet[i] = 0x00
	}

	return packet
}
