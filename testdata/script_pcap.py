#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Générateur PCAP réaliste pour Zandoli
# Version light : environ 50 hôtes, divers rôles, trafic léger
# Utilise Scapy uniquement en génération, sans injection réseau.

import ipaddress
import random
import string
from scapy.all import (
    Ether, ARP, IP, UDP, TCP,
    BOOTP, DHCP, Dot1Q, Raw, wrpcap
)

# -------------------------
# Configuration
# -------------------------
PCAP_FILE = "traffic_lab.pcap"
SUBNET = "192.168.50.0/24"
DNS_IP = "192.168.50.53"
VLAN_ID = 10

ROLE_COUNTS = {
    "ad": 1,
    "router": 1,
    "windows_client": 10,
    "linux_client": 5,
    "nas": 2,
    "firewall": 1,
    "voip": 10,
    "iot": 10,
    "webserver": 5,
    "local_server": 5
}

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

# -------------------------
# Générateurs utilitaires
# -------------------------
def rand_mac():
    return "02:00:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def gen_hostname(prefix):
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
    return f"{prefix}-{suffix}"

def build_hosts():
    net = ipaddress.ip_network(SUBNET, strict=False)
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
            mac = rand_mac()
            hostname = gen_hostname(role.upper())
            hosts.append({
                "ip": ip,
                "mac": mac,
                "role": role,
                "os": osfam,
                "ttl": ttl,
                "hostname": hostname
            })
    return hosts

# -------------------------
# Paquets simulés
# -------------------------
def gen_packets(hosts):
    packets = []

    for h in hosts:
        # ARP who-has (chaque hôte)
        arp = Ether(src=h["mac"], dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=h["ip"], pdst="192.168.50.1")
        packets.append(arp)

        # DHCP Discover (clients)
        if h["role"] in ("windows_client", "linux_client", "voip", "iot"):
            xid = random.randint(1, 0xFFFFFFFF)
            ether = Ether(src=h["mac"], dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src="0.0.0.0", dst="255.255.255.255")
            udp = UDP(sport=68, dport=67)
            bootp = BOOTP(chaddr=bytes.fromhex(h["mac"].replace(":", "")), xid=xid)
            dhcp = DHCP(options=[("message-type", "discover"), "end"])
            packets.append(ether / ip / udp / bootp / dhcp)

        # VLAN ping
        if random.random() < 0.1:
            vlanpkt = Ether(src=h["mac"], dst="ff:ff:ff:ff:ff:ff") / \
                      Dot1Q(vlan=VLAN_ID) / \
                      IP(src=h["ip"], dst="192.168.50.1", ttl=h["ttl"]) / \
                      UDP(sport=55555, dport=55555) / Raw(b"vlan-probe")
            packets.append(vlanpkt)

        # DNS query
        dnsq = Ether(src=h["mac"]) / IP(src=h["ip"], dst=DNS_IP, ttl=h["ttl"]) / \
               UDP(sport=random.randint(1024, 65535), dport=53) / Raw(b"dummy-dns")
        packets.append(dnsq)

        # TCP SYN vers port intéressant
        dport = random.choice([80, 443, 445])
        syn = Ether(src=h["mac"]) / IP(src=h["ip"], dst="192.168.50.1", ttl=h["ttl"]) / \
              TCP(sport=random.randint(1024, 65535), dport=dport, flags="S", seq=random.randint(0, 2**32-1))
        packets.append(syn)

    return packets

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    hosts = build_hosts()
    pkts = gen_packets(hosts)
    wrpcap(PCAP_FILE, pkts)
    print(f"✅ PCAP généré avec {len(pkts)} paquets dans {PCAP_FILE}")

