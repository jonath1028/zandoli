from scapy.all import (
    Ether, IP, UDP, TCP, BOOTP, DHCP, Dot1Q, EAPOL, LLC,
    wrpcap, Raw, DNS, DNSQR
)

packets = []

BASE_MAC = [0x00, 0x0c, 0x29]
BASE_IP = [192, 168, 1, 1]

def mac(i):
    return ':'.join(f'{x:02x}' for x in BASE_MAC + [(i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff])

def ip(i):
    return '.'.join(str(BASE_IP[0] + (i >> 16) % 10), str(BASE_IP[1]), str((i >> 8) % 256), str(i % 256))

for i in range(50000):
    src_mac = mac(i)
    src_ip = f"10.0.{(i // 256) % 256}.{i % 256}"
    dst_ip = f"10.1.{(i // 256) % 256}.{i % 256}"

    # DHCP Discover
    packets.append(
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(src_mac.replace(':', '')), xid=0x10000000 + i) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    # DNS Query
    packets.append(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src_ip, dst="8.8.8.8") /
        UDP(sport=12345, dport=53) /
        DNS(qr=0, qd=DNSQR(qname=f"host{i}.test"))
    )

    # LLMNR
    packets.append(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src_ip, dst="224.0.0.252") /
        UDP(sport=5355, dport=5355) /
        DNS(qr=0, qd=DNSQR(qname=f"host{i}"))
    )

    # ARP VLAN dummy (optional)
    packets.append(
        Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) /
        Dot1Q(vlan=10) /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=1234, dport=1234) /
        Raw(load="VLAN test")
    )

# Export
wrpcap("testdata/multi_protocol_50k.pcap", packets)

