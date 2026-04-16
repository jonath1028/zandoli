// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

package analyzer

import (
	"errors"

	"zandoli/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParseEAPOLPacket detects 802.1X (EAPOL) packets and returns a ParsedRecord.
func ParseEAPOLPacket(pkt model.PacketEvent) (*ParsedRecord, error) {
	if pkt.Payload == nil {
		return nil, errors.New("empty payload")
	}

	packet := gopacket.NewPacket(pkt.Payload, layers.LayerTypeEthernet, gopacket.Default)
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, nil
	}
	eth := ethLayer.(*layers.Ethernet)

	if eth.EthernetType != 0x888e {
		return nil, nil
	}

	// Create the base record
	record := &ParsedRecord{
		MAC:       pkt.SrcMAC,
		Protocols: []string{"802.1X"},
		Source:    "passive",
		FirstSeen: pkt.Timestamp,
		LastSeen:  pkt.Timestamp,
		L2: L2Info{
			EAPOL: true,
		},
	}

	// Try to parse the EAPOL payload to extract EAP information
	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer != nil {
		eapol := eapolLayer.(*layers.EAPOL)

		// Check if it is an EAP packet (Type 0)
		if eapol.Type == layers.EAPOLTypeEAP {
			eapLayer := packet.Layer(layers.LayerTypeEAP)
			if eapLayer != nil {
				eap := eapLayer.(*layers.EAP)

				// Check if it is an EAP Request/Identity (Code 1, Type 1)
				if eap.Code == layers.EAPCodeRequest && eap.Type == layers.EAPTypeIdentity {
					record.Role = "switch"
					// Extract the identity if present
					if len(eap.TypeData) > 0 {
						record.Info = "identity=" + string(eap.TypeData)
					}
				} else if eap.Code == layers.EAPCodeResponse && eap.Type == layers.EAPTypeIdentity {
					record.Role = "client"
					// Extract the identity if present
					if len(eap.TypeData) > 0 {
						record.Info = "identity=" + string(eap.TypeData)
					}
				}
			}
		}
	}

	// If no specific role was set, keep the default behavior
	if record.Role == "" {
		record.Role = "client"
	}

	// Log successful 802.1X parsing with key fields
	// Note: This is a minimal log inside the parser - most logging is done at dispatcher level
	return record, nil
}
