#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Zandoli – Realistic PCAP Generator (Scapy 2.6.1 compatible)
# Protocoles : LLDP, CDP, ARP, DHCP (DORA), DNS, mDNS, LLMNR, NBNS (Raw),
#              TCP SYN (80/443/445) avec options par OS, VLAN 802.1Q
# EXCLU (pour compat Scapy 2.6.1) : EAPOL/802.1X, STP/BPDU

import ipaddress
import random
import string
import time

from scapy.all import (
    Ether, ARP, IP, UDP, TCP, BOOTP, DHCP, Dot1Q, Raw,
    DNS, DNSQR, DNSRR, PcapWriter
)

# Contrib (présents en 2.6.1)
from scapy.contrib.lldp import (
    LLDPDU, LLDPDUChassisID, LLDPDUPortID, LLDPDUTimeToLive, LLDPDUSystemName
)
from scapy.contrib.cdp import (
    CDPv2_HDR, CDPMsgDeviceID, CDPMsgPortID,
    CDPMsgSoftwareVersion, CDPMsgPlatform
)

# -------------------------
# Configuration générale
# -------------------------
PCAP_FILE = "traffic_lab_realistic.pcap"
SUBNET = "192.168.50.0/24"
GATEWAY_IP = "192.168.50.1"
DNS_IP = "192.168.50.53"
DOMAIN = "lab.local"

# VLANs plausibles
VLAN_DATA = 10
VLAN_VOICE = 20
VLAN_SERVERS = 30

# Rôles (~50 hôtes)
ROLE_COUNTS = {
    "ad": 1,
    "router": 1,
    "firewall": 1,
    "windows_client": 10,
    "linux_client": 5,
    "nas": 2,
    "voip": 10,
    "iot": 10,
    "webserver": 5,
    "local_server": 5
}

# TTL plausibles par OS
OS_TTL = {
    "windows": 128,
    "linux": 64,
    "cisco": 255,
    "fortinet": 255,
    "voip": 64,
    "iot": 64,
    "nas": 64,
    "web": 64,
}

# OUIs indicatifs (MAC réalistes)
OUI = {
    "cisco":  "00:1B:54",
    "fortinet":"00:09:0F",
    "polycom": "00:04:F2",
    "raspi":   "B8:27:EB",
    "synology":"00:11:32",
    "qnap":    "00:08:9B",
    "generic": "02:00:00"
}

random.seed(42)

# -------------------------
# Utilitaires
# -------------------------
def rand_mac_from_oui(oui):
    base = [int(x, 16) for x in oui.split(":")]
    tail = [random.randrange(0, 256) for _ in range(3)]
    mac = base + tail
    return ":".join(f"{b:02x}" for b in mac)

def gen_hostname(prefix):
    return f"{prefix}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=4))}"

def prlist_default():
    # DHCP Parameter Request List (commune)
    return b"\x01\x03\x06\x0f\x1c\x33\x3a\x3b\x36\x3c"

def chaddr_bytes(mac):
    raw = bytes.fromhex(mac.replace(":", ""))
    return raw + b"\x00" * (16 - len(raw))

def tcp_opts_for_os(osfam):
    ts_val = random.randint(1_000_000, 9_999_999)
    if osfam == "windows":
        return [
            ("MSS", 1460), ("NOP", None), ("WS", 8),
            ("NOP", None), ("NOP", None), ("SAckOK", b"")
        ]
    elif osfam in ("linux", "web", "nas", "iot", "voip"):
        return [
            ("MSS", 1460), ("SAckOK", b""),
            ("Timestamp", (ts_val, 0)), ("NOP", None), ("WS", 7)
        ]
    elif osfam == "cisco":
        return [("MSS", 1460), ("NOP", None), ("WS", 6)]
    elif osfam == "fortinet":
        return [("MSS", 1460), ("SAckOK", b""), ("WS", 7)]
    else:
        return [("MSS", 1460), ("WS", 7)]

def win_for_os(osfam):
    if osfam == "windows":
        return 64240
    elif osfam in ("linux", "web", "nas", "iot", "voip"):
        return 29200
    elif osfam in ("cisco", "fortinet"):
        return 65535
    return 29200

def dhcp_opts_offer(server_ip, mask, router, dns, domain, lease=86400):
    return [
        ("message-type", "offer"),
        ("server_id", server_ip),
        ("lease_time", lease),
        ("subnet_mask", mask),
        ("router", router),
        ("name_server", dns),
        ("domain", domain),
        ("renewal_time", int(lease*0.5)),
        ("rebinding_time", int(lease*0.875)),
        "end",
    ]

def dhcp_opts_ack(server_ip, mask, router, dns, domain, lease=86400):
    return [
        ("message-type", "ack"),
        ("server_id", server_ip),
        ("lease_time", lease),
        ("subnet_mask", mask),
        ("router", router),
        ("name_server", dns),
        ("domain", domain),
        ("renewal_time", int(lease*0.5)),
        ("rebinding_time", int(lease*0.875)),
        "end",
    ]

# -------------------------
# Inventaire des hôtes
# -------------------------
def build_hosts(subnet):
    net = ipaddress.ip_network(subnet, strict=False)
    ip_iter = (str(ip) for ip in net.hosts())
    hosts = []

    for role, count in ROLE_COUNTS.items():
        for _ in range(count):
            ip = next(ip_iter)
            if role in ("ad", "windows_client"):
                osfam = "windows"
            elif role in ("linux_client", "iot", "voip", "nas", "webserver", "local_server"):
                osfam = "linux"
            elif role == "router":
                osfam = "cisco"
            elif role == "firewall":
                osfam = "fortinet"
            else:
                osfam = "linux"

            ttl = OS_TTL.get(osfam, 64)

            if role == "router":
                mac = rand_mac_from_oui(OUI["cisco"])
            elif role == "firewall":
                mac = rand_mac_from_oui(OUI["fortinet"])
            elif role == "voip":
                mac = rand_mac_from_oui(OUI["polycom"])
            elif role == "iot":
                mac = rand_mac_from_oui(OUI["raspi"])
            elif role == "nas":
                mac = rand_mac_from_oui(random.choice([OUI["synology"], OUI["qnap"]]))
            else:
                mac = rand_mac_from_oui(OUI["generic"])

            hostname = {
                "ad": gen_hostname("AD"),
                "router": gen_hostname("RTR"),
                "firewall": gen_hostname("FW"),
                "windows_client": gen_hostname("WIN11"),
                "linux_client": gen_hostname("LIN"),
                "nas": gen_hostname("NAS"),
                "voip": gen_hostname("VOIP"),
                "iot": gen_hostname("IOT"),
                "webserver": gen_hostname("WEB"),
                "local_server": gen_hostname("SRV"),
            }[role]

            vlan = VLAN_DATA
            if role == "voip":
                vlan = VLAN_VOICE
            elif role in ("webserver", "local_server", "nas", "ad"):
                vlan = VLAN_SERVERS

            hosts.append({
                "ip": ip,
                "mac": mac,
                "role": role,
                "os": osfam,
                "ttl": ttl,
                "hostname": hostname,
                "vlan": vlan
            })
    return hosts

# -------------------------
# Génération de paquets
# -------------------------
def add(pcap, pkt, t):
    pkt.time = t
    pcap.write(pkt)

def gen_pcap():
    hosts = build_hosts(SUBNET)
    pcap = PcapWriter(PCAP_FILE, sync=True)
    t0 = time.time()

    router = next(h for h in hosts if h["role"] == "router")
    firewall = next(h for h in hosts if h["role"] == "firewall")
    ad = next(h for h in hosts if h["role"] == "ad")
    dhcp_server = ad  # plausible: AD fait DHCP & DNS

    # 1) LLDP & CDP (control-plane L2)
    add(pcap,
        Ether(src=router["mac"], dst="01:80:c2:00:00:0e", type=0x88cc) /
        LLDPDU() /
        LLDPDUChassisID(subtype=7, id=router["mac"]) /
        LLDPDUPortID(subtype=5, id="Gi0/1") /
        LLDPDUTimeToLive(ttl=120) /
        LLDPDUSystemName(system_name=router["hostname"]),
        t0 + 0.05)

    add(pcap,
        Ether(src=router["mac"], dst="01:00:0c:cc:cc:cc", type=0x2000) /
        CDPv2_HDR() /
        CDPMsgDeviceID(val=router["hostname"]) /
        CDPMsgPortID(iface="Gi0/1") /
        CDPMsgPlatform(val="Cisco ISR") /
        CDPMsgSoftwareVersion(val="IOS XE 17.9"),
        t0 + 0.15)

    # 2) ARP who-has de quelques hôtes vers la GW
    for i, h in enumerate(hosts[:20]):
        add(pcap,
            Ether(src=h["mac"], dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc=h["mac"], psrc=h["ip"], pdst=GATEWAY_IP),
            t0 + 0.40 + i*0.002)

    # 3) DHCP 4-way (DORA) pour ~12 clients
    mask = "255.255.255.0"; lease = 86400
    dhcp_clients = [x for x in hosts if x["role"] in ("windows_client", "linux_client", "voip", "iot")][:12]
    for i, cli in enumerate(dhcp_clients):
        xid = random.randint(1, 0xFFFFFFFF)
        # DISCOVER (broadcast)
        add(pcap,
            Ether(src=cli["mac"], dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, chaddr=chaddr_bytes(cli["mac"]), xid=xid, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), ("param_req_list", prlist_default()), ("hostname", cli["hostname"]), "end"]),
            t0 + 1.00 + i*0.010)

        # OFFER (server -> broadcast)
        add(pcap,
            Ether(src=dhcp_server["mac"], dst="ff:ff:ff:ff:ff:ff") /
            IP(src=dhcp_server["ip"], dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, chaddr=chaddr_bytes(cli["mac"]), xid=xid, yiaddr=cli["ip"], siaddr=dhcp_server["ip"]) /
            DHCP(options=dhcp_opts_offer(dhcp_server["ip"], mask, GATEWAY_IP, DNS_IP, DOMAIN, lease)),
            t0 + 1.03 + i*0.010)

        # REQUEST (broadcast)
        add(pcap,
            Ether(src=cli["mac"], dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(op=1, chaddr=chaddr_bytes(cli["mac"]), xid=xid, flags=0x8000) /
            DHCP(options=[("message-type", "request"), ("requested_addr", cli["ip"]), ("server_id", dhcp_server["ip"]), ("hostname", cli["hostname"]), "end"]),
            t0 + 1.06 + i*0.010)

        # ACK (server -> broadcast)
        add(pcap,
            Ether(src=dhcp_server["mac"], dst="ff:ff:ff:ff:ff:ff") /
            IP(src=dhcp_server["ip"], dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, chaddr=chaddr_bytes(cli["mac"]), xid=xid, yiaddr=cli["ip"], siaddr=dhcp_server["ip"]) /
            DHCP(options=dhcp_opts_ack(dhcp_server["ip"], mask, GATEWAY_IP, DNS_IP, DOMAIN, lease)),
            t0 + 1.09 + i*0.010)

    # 4) DNS (queries + réponses A) + mDNS + LLMNR + NBNS (Raw)
    # Inventaire DNS de base
    dns_records = { f"{ad['hostname']}.{DOMAIN}.": ad["ip"] }
    for s in [x for x in hosts if x["role"] in ("webserver", "nas")][:4]:
        dns_records[f"{s['hostname']}.{DOMAIN}."] = s["ip"]

    # DNS unicast
    for i, h in enumerate(hosts[:20]):
        qname, ans_ip = random.choice(list(dns_records.items()))
        sport = random.randint(1024, 65535)
        add(pcap,
            Ether(src=h["mac"], dst=rand_mac_from_oui(OUI["generic"])) /
            IP(src=h["ip"], dst=DNS_IP, ttl=OS_TTL.get(h["os"], 64)) /
            UDP(sport=sport, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=qname)),
            t0 + 1.50 + i*0.004)

        add(pcap,
            Ether(src=dhcp_server["mac"], dst=h["mac"]) /
            IP(src=DNS_IP, dst=h["ip"], ttl=64) /
            UDP(sport=53, dport=sport) /
            DNS(qr=1, aa=1, qd=DNSQR(qname=qname),
                an=DNSRR(rrname=qname, type="A", ttl=300, rdata=ans_ip)),
            t0 + 1.52 + i*0.004)

    # mDNS: query + réponse A + PTR/SRV/TXT
    mdns_qname = f"{hosts[0]['hostname']}.local"
    add(pcap,
        Ether(src=hosts[1]["mac"], dst="01:00:5e:00:00:fb") /
        IP(src=hosts[1]["ip"], dst="224.0.0.251", ttl=hosts[1]["ttl"]) /
        UDP(sport=5353, dport=5353) /
        DNS(rd=0, qd=DNSQR(qname=mdns_qname)),
        t0 + 1.80)

    add(pcap,
        Ether(src=hosts[0]["mac"], dst=hosts[1]["mac"]) /
        IP(src=hosts[0]["ip"], dst=hosts[1]["ip"], ttl=hosts[0]["ttl"]) /
        UDP(sport=5353, dport=5353) /
        DNS(qr=1, aa=1, qd=DNSQR(qname=mdns_qname),
            an=DNSRR(rrname=mdns_qname, type="A", ttl=120, rdata=hosts[0]["ip"])),
        t0 + 1.82)

    add(pcap,
        Ether(src=hosts[0]["mac"], dst="01:00:5e:00:00:fb") /
        IP(src=hosts[0]["ip"], dst="224.0.0.251", ttl=hosts[0]["ttl"]) /
        UDP(sport=5353, dport=5353) /
        DNS(qr=1, aa=1,
            an=DNSRR(rrname="_workstation._tcp.local", type="PTR", ttl=120,
                     rdata=f"{hosts[0]['hostname']}._workstation._tcp.local"),
            ns=DNSRR(rrname=f"{hosts[0]['hostname']}._workstation._tcp.local",
                     type="SRV", ttl=120, rdata=f"{hosts[0]['hostname']}.local"),
            ar=DNSRR(rrname=f"{hosts[0]['hostname']}._workstation._tcp.local",
                     type="TXT", ttl=120, rdata="txtvers=1")),
        t0 + 1.84)

    # LLMNR (DNS-compatible over 5355)
    llmnr_name = hosts[2]["hostname"]
    add(pcap,
        Ether(src=hosts[3]["mac"], dst="01:00:5e:00:00:fc") /
        IP(src=hosts[3]["ip"], dst="224.0.0.252", ttl=hosts[3]["ttl"]) /
        UDP(sport=5355, dport=5355) /
        DNS(rd=0, qd=DNSQR(qname=llmnr_name)),
        t0 + 1.90)

    add(pcap,
        Ether(src=hosts[2]["mac"], dst=hosts[3]["mac"]) /
        IP(src=hosts[2]["ip"], dst=hosts[3]["ip"], ttl=hosts[2]["ttl"]) /
        UDP(sport=5355, dport=5355) /
        DNS(qr=1, aa=1, qd=DNSQR(qname=llmnr_name),
            an=DNSRR(rrname=llmnr_name, type="A", ttl=30, rdata=hosts[2]["ip"])),
        t0 + 1.92)

    # NBNS (NetBIOS) – on reste en Raw pour compatibilité et simplicité
    add(pcap,
        Ether(src=hosts[5]["mac"], dst="ff:ff:ff:ff:ff:ff") /
        IP(src=hosts[5]["ip"], dst="255.255.255.255", ttl=hosts[5]["ttl"]) /
        UDP(sport=137, dport=137) / Raw(b"\x00\x00"),
        t0 + 1.96)

    add(pcap,
        Ether(src=hosts[4]["mac"], dst=hosts[5]["mac"]) /
        IP(src=hosts[4]["ip"], dst=hosts[5]["ip"], ttl=hosts[4]["ttl"]) /
        UDP(sport=137, dport=137) / Raw(b"\x00\x01\x00\x00"),
        t0 + 1.98)

    # 5) TCP SYN (80/443/445) avec options par OS + VLAN (sur un sous-ensemble)
    def syn_pkt(h, dst_ip, dport):
        opts = tcp_opts_for_os(h["os"])
        win = win_for_os(h["os"])
        l3 = IP(src=h["ip"], dst=dst_ip, ttl=h["ttl"])
        l4 = TCP(sport=random.randint(1024, 65535), dport=dport, flags="S",
                 seq=random.randint(0, 2**32-1), window=win, options=opts)
        base = Ether(src=h["mac"])
        # Tag VLAN pour ~25 % des paquets
        if h["vlan"] in (VLAN_DATA, VLAN_VOICE, VLAN_SERVERS) and random.random() < 0.25:
            return base / Dot1Q(vlan=h["vlan"]) / l3 / l4
        return base / l3 / l4

    syn_targets = []
    # Clients -> SMB(445) vers AD ; Servers -> 80/443 vers GW
    for h in hosts:
        if h["role"] in ("windows_client", "linux_client"):
            syn_targets.append((h, ad["ip"], 445))
        if h["role"] in ("webserver", "local_server"):
            syn_targets.append((h, GATEWAY_IP, random.choice([80, 443])))

    for i, (h, dip, dp) in enumerate(syn_targets[:60]):
        add(pcap, syn_pkt(h, dip, dp), t0 + 2.10 + i*0.003)

    # 6) Probes UDP taggés VLAN (quelques échantillons)
    for i, h in enumerate(random.sample(hosts, k=min(10, len(hosts)))):
        add(pcap,
            Ether(src=h["mac"], dst="ff:ff:ff:ff:ff:ff") /
            Dot1Q(vlan=h["vlan"]) /
            IP(src=h["ip"], dst=GATEWAY_IP, ttl=h["ttl"]) /
            UDP(sport=55555, dport=55555) / Raw(b"vlan-probe"),
            t0 + 2.50 + i*0.002)

    pcap.close()
    print(f"✅ PCAP généré : {PCAP_FILE}")
    return PCAP_FILE


if __name__ == "__main__":
    gen_pcap()

