package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"zandoli/pkg/logger"
	"zandoli/pkg/sniffer"
)

func AnalyzeDHCP(packet gopacket.Packet) {
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return
	}

	dhcp, _ := dhcpLayer.(*layers.DHCPv4)
	srcIP := dhcp.ClientIP
	if srcIP.String() == "0.0.0.0" {
		srcIP = dhcp.YourClientIP
	}

	host := sniffer.FindHostByIP(srcIP)
	if host == nil {
		return
	}

	host.ProtocolsSeen["DHCP"] = true

	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptHostname:
			host.Hostname = string(opt.Data)
		case layers.DHCPOptDomainName:
			host.DomainName = string(opt.Data)
		case 54:
			host.Metadata["dhcp_server"] = string(opt.Data)
		case 82:
			host.Metadata["relay_agent"] = string(opt.Data)
		}
	}

	logger.Logger.Debug().Msgf("[DHCP] Updated host %s with DHCP info", host.IP)
}
