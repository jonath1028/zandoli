from scapy.all import (
    Ether, IP, UDP, TCP, BOOTP, DHCP,
    Dot1Q, EAPOL, LLC, wrpcap, Raw, DNS, DNSQR
)

packets = []

# ========== DHCP ==========
packets.append(
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0b:82:01:fc:42") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=b'\x00\x0b\x82\x01\xfc\x42', xid=0x10000001) /
    DHCP(options=[("message-type", "discover"), "end"])
)

# ========== LLDP ==========
lldp_payload = (
    b'\x02\x07\x04\x00\x0c\x29\x9c\x8e\x35' +
    b'\x04\x03\x02\x01' +
    b'\x06\x02\x00\x78' +
    b'\x00\x00'
)
packets.append(
    Ether(dst="01:80:c2:00:00:0e", src="00:0c:29:9c:8e:35", type=0x88cc) /
    Raw(load=lldp_payload)
)

# ========== 802.1X (EAPOL) ==========
packets.append(
    Ether(dst="01:80:c2:00:00:03", src="00:0c:29:9c:8e:35", type=0x888e) /
    EAPOL(version=1, type=0, len=0)
)

# ========== VLAN (802.1Q) ==========
packets.append(
    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:0c:29:9c:8e:35") /
    Dot1Q(vlan=10) /
    IP(src="192.168.0.1", dst="192.168.0.255") /
    UDP(sport=1234, dport=1234) /
    Raw(load="VLAN test")
)

# ========== CDP (Cisco Discovery Protocol) ==========
cdp_payload = (
    b'\x02\x01\x00\x0c' + b'\x63\x69\x73\x63\x6f\x2d\x64\x65\x76' +  # Device ID
    b'\x04\x01\x00\x04' + b'\x47\x31\x2f\x31' +                      # Port ID
    b'\x06\x00\x00\x78' +                                            # TTL
    b'\x00\x00'                                                      # End
)
packets.append(
    Ether(dst="01:00:0c:cc:cc:cc", src="00:0c:29:aa:bb:cc", type=0x2000) /
    Raw(load=cdp_payload)
)

# ========== STP ==========
stp_payload = b'\x00' * 35
packets.append(
    Ether(dst="01:80:c2:00:00:00", src="00:0c:29:11:22:33", type=0x0000) /
    LLC(dsap=0x42, ssap=0x42, ctrl=0x03) /
    Raw(load=b"\x00" * 32)
)
# ========== SMB ==========
packets.append(
    Ether(src="00:0c:29:44:55:66", dst="00:50:56:c0:00:08") /
    IP(src="192.168.1.50", dst="192.168.1.1") /
    TCP(sport=12345, dport=445, flags="S") /
    Raw(load="SMB")
)

# ========== NetBIOS Name Service (manuel) ==========
netbios_payload = (
    b'\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # standard NBNS header
    b'\x20' +                                     # name length
    b'\x43' * 32 +                                # dummy name (C's)
    b'\x00\x20\x00\x01'                           # type A, class IN
)
packets.append(
    Ether(src="00:0c:29:77:88:99", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="192.168.1.52", dst="192.168.1.255") /
    UDP(sport=137, dport=137) /
    Raw(load=netbios_payload)
)

# ========== LLMNR ==========
packets.append(
    Ether(src="00:0c:29:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="192.168.1.53", dst="224.0.0.252") /
    UDP(sport=5355, dport=5355) /
    DNS(qr=0, qd=DNSQR(qname="host"))
)

# ========== mDNS ==========
packets.append(
    Ether(src="00:0c:29:bb:bb:bb", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="192.168.1.54", dst="224.0.0.251") /
    UDP(sport=5353, dport=5353) /
    DNS(qr=0, qd=DNSQR(qname="service.local"))
)

# ========== DNS ==========
packets.append(
    Ether(src="00:0c:29:cc:cc:cc", dst="ff:ff:ff:ff:ff:ff") /
    IP(src="192.168.1.55", dst="8.8.8.8") /
    UDP(sport=12345, dport=53) /
    DNS(qr=0, qd=DNSQR(qname="example.com"))
)

# ========== Export ==========
wrpcap("testdata/multi_protocol.pcap", packets)

