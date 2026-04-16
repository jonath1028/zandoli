// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Jonathan NOMED

//go:build !integration

package analyzer

import (
    "net"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

// buildUDPPacket creates a dummy Ethernet/IPv4/UDP packet with specified ports.
func buildUDPPacket(src, dst layers.UDPPort) []byte {
    eth := &layers.Ethernet{
        SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
        EthernetType: layers.EthernetTypeIPv4,
    }
    ip := &layers.IPv4{
        SrcIP:    net.IP{10, 0, 0, 1},
        DstIP:    net.IP{10, 0, 0, 2},
        Protocol: layers.IPProtocolUDP,
    }
    udp := &layers.UDP{
        SrcPort: src,
        DstPort: dst,
    }
    udp.SetNetworkLayerForChecksum(ip)

    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
    gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte("dummy")))
    return buf.Bytes()
}

