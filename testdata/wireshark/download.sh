#!/bin/bash
# Download Wireshark reference PCAPs for protocol parser validation.
# Run from the repo root: bash testdata/wireshark/download.sh
# Respects rate limiting: waits 25 seconds between downloads.

set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

BASE="https://wiki.wireshark.org/uploads/__moin_import__/attachments"

dl() {
    local out="$DIR/$1"
    local url="$BASE/$2"
    if [ -f "$out" ]; then
        echo "  skip (exists): $1"
        return
    fi
    echo -n "  downloading: $1 ... "
    if curl -fSL --retry 3 --retry-delay 10 -o "$out" "$url" 2>/dev/null; then
        # Decompress if gzipped
        if file "$out" | grep -q "gzip"; then
            mv "$out" "${out}.gz"
            gunzip "${out}.gz" 2>/dev/null || { echo "FAILED (decompress)"; rm -f "${out}.gz"; return; }
        fi
        echo "OK ($(wc -c < "$out") bytes)"
    else
        echo "FAILED"
        rm -f "$out"
    fi
    sleep 25
}

echo "=== Downloading Wireshark reference PCAPs ==="

# LLDP (3 variants)
dl lldp_minimal.pcap       "SampleCaptures/lldp.minimal.pcap"
dl lldp_detailed.pcap      "SampleCaptures/lldp.detailed.pcap"
dl lldpmed_civicloc.pcap   "SampleCaptures/lldpmed_civicloc.pcap"

# CDP
dl cdp_v2.pcap             "SampleCaptures/cdp_v2.pcap"
dl macsec_cdp.pcap         "SampleCaptures/macsec_cisco_trunk.pcap"

# DHCP
dl dhcp.pcap               "SampleCaptures/dhcpboot.pcap"
dl dhcp_inform.pcap        "SampleCaptures/dhcp-and-dyndns.pcap.gz"

# DNS
dl dns.pcap                "SampleCaptures/dns.cap"

# SSDP
dl ssdp.pcap               "SampleCaptures/SSDP.pcap"

# ARP
dl arp_storm.pcap          "SampleCaptures/arp-storm.pcap"

# SMB
dl smb_browser.pcapng      "SampleCaptures/smb-browser-elections.pcapng"

# 802.1X / EAPOL
dl eapol_wpa.pcap          "SampleCaptures/eapol-mka.pcap"

# TCP (OS fingerprinting)
dl tcp_ecn.pcap            "SampleCaptures/tcp-ecn-sample.pcap"

# IPv6 NDP
dl ipv6_ndp.pcap           "SampleCaptures/v6.pcap"

# HSRP (gateway redundancy)
dl hsrp_v1.pcap            "SampleCaptures/HSRP_with_ARP.cap"
dl hsrp_v2.pcap            "SampleCaptures/HSRPv2.cap"

# VRRP (gateway redundancy)
dl vrrp_v2.pcap            "SampleCaptures/vrrp.pcap"

echo ""
echo "=== Downloaded files ==="
ls -lhS "$DIR"/*.pcap "$DIR"/*.pcapng 2>/dev/null || echo "(none)"
