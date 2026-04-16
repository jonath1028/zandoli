#!/bin/bash
# Validate Zandoli protocol parsers against Wireshark reference PCAPs.
# Prerequisites: run download.sh first, then go build -o /tmp/zandoli ./cmd/zandoli
#
# Usage: bash testdata/wireshark/validate.sh

set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ZANDOLI="${ZANDOLI:-/tmp/zandoli}"

if [ ! -x "$ZANDOLI" ]; then
    echo "ERROR: $ZANDOLI not found. Run: go build -o /tmp/zandoli ./cmd/zandoli"
    exit 1
fi

PASS=0
FAIL=0
SKIP=0

test_pcap() {
    local pcap="$1"
    local name="$2"
    local expected_proto="$3"

    if [ ! -f "$pcap" ]; then
        echo "  SKIP: $name (file not found — run download.sh first)"
        SKIP=$((SKIP + 1))
        return
    fi

    local outdir="/tmp/zandoli_validate_${name}"
    rm -rf "$outdir"
    "$ZANDOLI" --pcap "$pcap" --formats json --output-dir "$outdir" >/dev/null 2>&1

    local json_file
    json_file=$(ls "$outdir"/*/hosts.json 2>/dev/null | head -1)
    if [ -z "$json_file" ]; then
        echo "  FAIL: $name (no output)"
        FAIL=$((FAIL + 1))
        return
    fi

    local result
    result=$(python3 -c "
import json
d=json.load(open('$json_file'))
hosts=d.get('hosts',[])
protos=set()
for h in hosts:
    for p in h.get('protocols',[]): protos.add(p)
print(f'{len(hosts)}|{\",\".join(sorted(protos))}')
")

    local hosts="${result%%|*}"
    local protos="${result##*|}"

    if echo "$protos" | grep -qi "$expected_proto"; then
        printf "  PASS: %-25s hosts=%-3s protocols=%s\n" "$name" "$hosts" "$protos"
        PASS=$((PASS + 1))
    else
        printf "  FAIL: %-25s expected=%s got=%s\n" "$name" "$expected_proto" "$protos"
        FAIL=$((FAIL + 1))
    fi

    rm -rf "$outdir"
}

echo "=== Zandoli Protocol Parser Validation ==="
echo ""

# LLDP
test_pcap "$DIR/lldp_minimal.pcap"      "lldp_minimal"      "LLDP"
test_pcap "$DIR/lldp_detailed.pcap"     "lldp_detailed"     "LLDP"
test_pcap "$DIR/lldpmed_civicloc.pcap"  "lldpmed_civicloc"  "LLDP"

# CDP / 802.1X
test_pcap "$DIR/cdp_v2.pcap"            "cdp_v2"            "CDP"
test_pcap "$DIR/macsec_cdp.pcap"        "macsec_cdp"        "802.1X"
test_pcap "$DIR/eapol_wpa.pcap"         "eapol_wpa"         "802.1X"

# DHCP
test_pcap "$DIR/dhcp.pcap"              "dhcp"              "DHCP"
test_pcap "$DIR/dhcp_inform.pcap"       "dhcp_inform"       "DHCP"

# DNS
test_pcap "$DIR/dns.pcap"               "dns"               "DNS"

# SSDP
test_pcap "$DIR/ssdp.pcap"              "ssdp"              "SSDP"

# ARP
test_pcap "$DIR/arp_storm.pcap"         "arp_storm"         "ARP"

# SMB
test_pcap "$DIR/smb_browser.pcapng"     "smb_browser"       "ARP"

# TCP
test_pcap "$DIR/tcp_ecn.pcap"           "tcp_ecn"           "TCP"

# IPv6 NDP
test_pcap "$DIR/ipv6_ndp.pcap"          "ipv6_ndp"          "NDP"

# HSRP (gateway redundancy)
test_pcap "$DIR/hsrp_v1.pcap"           "hsrp_v1"           "HSRP"
test_pcap "$DIR/hsrp_v2.pcap"           "hsrp_v2"           "HSRP"

# VRRP (gateway redundancy)
test_pcap "$DIR/vrrp_v2.pcap"           "vrrp_v2"           "VRRP"

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped ==="
[ "$FAIL" -eq 0 ] || exit 1
