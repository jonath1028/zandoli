# generate_dhcp_pcap.py
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, wrpcap

# DHCP Discover
discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0b:82:01:fc:42") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=b'\x00\x0b\x82\x01\xfc\x42', xid=0x10000001) /
    DHCP(options=[("message-type", "discover"), "end"])
)

# DHCP Offer
offer = (
    Ether(dst="00:0b:82:01:fc:42", src="02:42:ac:11:00:01") /
    IP(src="192.168.1.1", dst="255.255.255.255") /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="192.168.1.100", siaddr="192.168.1.1", chaddr=b'\x00\x0b\x82\x01\xfc\x42', xid=0x10000001) /
    DHCP(options=[("message-type", "offer"), "end"])
)

# DHCP Request
request = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0b:82:01:fc:42") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=b'\x00\x0b\x82\x01\xfc\x42', xid=0x10000001) /
    DHCP(options=[("message-type", "request"), "end"])
)

# DHCP Ack
ack = (
    Ether(dst="00:0b:82:01:fc:42", src="02:42:ac:11:00:01") /
    IP(src="192.168.1.1", dst="255.255.255.255") /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="192.168.1.100", siaddr="192.168.1.1", chaddr=b'\x00\x0b\x82\x01\xfc\x42', xid=0x10000001) /
    DHCP(options=[("message-type", "ack"), "end"])
)

# ========== LLDP ==========
lldp_payload = (
    b'\x02\x07\x04\x00\x0c\x29\x9c\x8e\x35'  # Chassis ID TLV
    b'\x04\x03\x02\x01'                      # Port ID TLV
    b'\x06\x02\x00\x78'                      # TTL TLV
    b'\x00\x00'                              # End of LLDPDU TLV
)
lldp = Ether(dst="01:80:c2:00:00:0e", src="00:0c:29:9c:8e:35", type=0x88cc) / Raw(load=lldp_payload)

# ========== 802.1X (EAPOL) ==========
eapol = Ether(dst="01:80:c2:00:00:03", src="00:0c:29:9c:8e:35", type=0x888e) / EAPOL(version=1, type=0, len=0)

# ========== VLAN (802.1Q) ==========
vlan = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0c:29:9c:8e:35") /
    Dot1Q(vlan=10) /
    IP(src="192.168.0.1", dst="192.168.0.255") /
    UDP(sport=1234, dport=1234) /
    Raw(load="VLAN test")
)

# ========== Export ==========
wrpcap("testdata/multi_protocol.pcap", [discover, lldp, eapol, vlan])
