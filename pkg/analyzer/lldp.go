// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

// Package analyzer provides LLDP packet detection for passive role inference.
package analyzer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseLLDPPacket detects LLDP packets and returns a structured ParsedRecord.
// Role is determined by analyzing System Capabilities TLV: router capability = "router", else "switch".
func ParseLLDPPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if pkt.Payload == nil {
		return nil, errors.New("empty payload")
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, nil // not Ethernet
	}
	eth := ethLayer.(*layers.Ethernet)

	if eth.EthernetType != 0x88cc {
		return nil, nil // not LLDP
	}

	// Analyse LLDP TLVs to determine the role and extract information
	role := "reseau" // default
	var info string
	var hostname string
	var managementIP net.IP
	var lldpInfo *model.LLDPInfo

	// LLDP TLVs start right after the 14-byte Ethernet header.
	// gopacket may decode LLDP into its own layer type, so use the raw
	// payload bytes to ensure our custom TLV parser always gets the data.
	if len(pkt.Payload) > 14 {
		role, info, hostname, managementIP, lldpInfo = parseLLDPCapabilities(pkt.Payload[14:])
	}

	record := &ParsedRecord{
		MAC:       pkt.SrcMAC,
		IP:        managementIP,
		Protocols: []string{"LLDP"},
		Role:      role,
		Info:      info,
		Hostname:  hostname,
		Source:    "passive",
		FirstSeen: pkt.Timestamp,
		LastSeen:  pkt.Timestamp,
		LLDP:      lldpInfo,
		L2: L2Info{
			LLDP: true,
		},
	}

	// Log successful LLDP parsing with key fields
	// Note: This is a minimal log inside the parser - most logging is done at dispatcher level
	return record, nil
}

// parseLLDPCapabilities analyses LLDP TLVs to detect system capabilities and extract information
func parseLLDPCapabilities(payload []byte) (string, string, string, net.IP, *model.LLDPInfo) {
	reader := bytes.NewReader(payload)
	role := "reseau"
	var infoParts []string
	var systemName string
	var systemDescription string
	var portID string
	var chassisID string
	var managementIP net.IP
	var capabilities []string
	var mgmtAddresses []string

	for {
		// Read the TLV header (Type + Length on 2 bytes)
		var tlvHeader uint16
		err := binary.Read(reader, binary.BigEndian, &tlvHeader)
		if err != nil {
			break
		}

		tlvType := tlvHeader >> 9
		tlvLength := tlvHeader & 0x01FF

		// TLV de fin (Type 0)
		if tlvType == 0 {
			break
		}

		data := make([]byte, tlvLength)
		_, err = reader.Read(data)
		if err != nil {
			break
		}

		switch tlvType {
		case 1: // Chassis ID TLV
			if len(data) > 0 {
				chassisID = string(data)
			}
		case 2: // Port ID TLV
			if len(data) > 0 {
				portID = string(data)
				infoParts = append(infoParts, "port="+portID)
			}
		case 5: // System Name TLV
			if len(data) > 0 {
				systemName = string(data)
			}
		case 6: // System Description TLV
			if len(data) > 0 {
				systemDescription = string(data)
			}
		case 7: // System Capabilities TLV
			if len(data) >= 4 {
				enabledCapabilities := binary.BigEndian.Uint16(data[2:4])

				// Analyse capability bits to determine the role
				// Bit 0 (0x01) = Router capability
				// Bit 1 (0x02) = Repeater capability
				// Bit 2 (0x04) = Bridge capability (switch)
				// Bit 3 (0x08) = WLAN Access Point capability
				// Bit 4 (0x10) = Telephone capability
				// Bit 5 (0x20) = DOCSIS Cable Device capability
				// Bit 6 (0x40) = Station capability (host)
				// Bit 7 (0x80) = Other capability

				// Build the list of decoded capabilities
				if enabledCapabilities&0x01 != 0 {
					capabilities = append(capabilities, "Router")
					role = "reseau"
				}
				if enabledCapabilities&0x02 != 0 {
					capabilities = append(capabilities, "Repeater")
				}
				if enabledCapabilities&0x04 != 0 {
					capabilities = append(capabilities, "Bridge")
					if role == "" {
						role = "reseau"
					}
				}
				if enabledCapabilities&0x08 != 0 {
					capabilities = append(capabilities, "WLAN AP")
				}
				if enabledCapabilities&0x10 != 0 {
					capabilities = append(capabilities, "Telephone")
				}
				if enabledCapabilities&0x20 != 0 {
					capabilities = append(capabilities, "DOCSIS")
				}
				if enabledCapabilities&0x40 != 0 {
					capabilities = append(capabilities, "Station")
				}
				if enabledCapabilities&0x80 != 0 {
					capabilities = append(capabilities, "Other")
				}
			}
		case 8: // Management Address TLV
			if len(data) >= 4 {
				// Les 4 premiers bytes contiennent l'adresse IP de gestion
				mgmtIP := net.IP(data[:4])
				if mgmtIP != nil && !mgmtIP.IsUnspecified() && mgmtIP.To4() != nil {
					managementIP = mgmtIP
					mgmtAddresses = append(mgmtAddresses, mgmtIP.String())
					infoParts = append(infoParts, "MgmtIP:"+mgmtIP.String())
				}
			}
		}
	}

	// Build the info string
	info := ""
	if systemDescription != "" {
		if info != "" {
			info += " "
		}
		info += "model=" + systemDescription
	}
	if len(infoParts) > 0 {
		if info != "" {
			info += " "
		}
		info += infoParts[0]
		for i := 1; i < len(infoParts); i++ {
			info += " " + infoParts[i]
		}
	}

	// Create the LLDPInfo structure
	lldpInfo := &model.LLDPInfo{
		ChassisID:    chassisID,
		PortID:       portID,
		SysName:      systemName,
		SysDescr:     systemDescription,
		MgmtAddrs:    mgmtAddresses,
		Capabilities: capabilities,
	}

	return role, info, systemName, managementIP, lldpInfo
}
