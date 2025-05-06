# Zandoli

**Zandoli** is a stealthy internal network reconnaissance tool designed for professional penetration testers. It combines passive traffic analysis with selective active probing to map and assess internal infrastructures without triggering defensive mechanisms or raising noise. The tool emphasizes operational discretion, clean design, and real-time visibility.

---

## 🔍 Key Features

* **Passive Discovery** via LLDP, DHCP, ARP, VLAN tagging, EAPOL
* **Active ARP Scanning** with both standard and stealth modes (unicast, no retries)
* **Lightweight OS Fingerprinting** using SYN/SYN-ACK patterns on configurable ports
* **Anomaly Detection**: identify duplicated MACs, IP conflicts, or irregular bindings
* **Subnet Auto-Discovery**: dynamically detect /24 subnets for targeted scanning
* **MAC Vendor Identification** through OUI file parsing
* **Offline `.pcap` Parsing** to extract passive data from captured sessions
* **Real-Time Export** to JSON, CSV, and HTML formats
* **Execution Modes**: `--passive`, `--active`, `--combined`, `--pcap`
* **Timeouts & Signal Handling**: graceful exits and global scan duration control
* **Configurable Interface, Exclusions, and Rate Limits** via YAML

---

## 📦 Installation

### Requirements

* [Go](https://golang.org/doc/install) 1.20+
* Dependencies:

```bash
go get github.com/google/gopacket@v1.1.19
go get github.com/rs/zerolog@v1.34.0
go get github.com/cheggaaa/pb/v3@v3.1.7
go get gopkg.in/yaml.v2@v2.4.0
```

### Build

```bash
git clone https://github.com/your-org/zandoli.git
cd zandoli
go build -o zandoli ./zandoli
```

---

## ⚙️ Usage

```bash
sudo ./zandoli --mode=combined --interface=eth0 --config=conf/config.yaml
```

* `--mode`: passive | active | combined | pcap
* `--interface`: network interface (mandatory)
* `--config`: path to YAML configuration file

### Sample `config.yaml`

```yaml
interface: eth0
oui_path: conf/oui.txt
capture_timeout_seconds: 300

arp_stealth:
  enabled: true
  max_requests_per_burst: 10
  max_bursts_per_25s: 1
  delay_between_requests: "random(55-95)"

exclude_subnets:
  - 192.168.1.0/24

---

## 🧪 Typical Use Cases

* Silent internal network enumeration during a grey-box engagement
* VLAN discovery and misconfiguration analysis
* Detection of rogue bridges or misconfigured multi-homed hosts
* Pre-exploitation reconnaissance to guide lateral movement

---

## ⚠️ Limitations

* IPv6 is not supported in this version
* No SNMP or NetBIOS enumeration
* Only tested on Linux platforms
* No live dashboard or API interface (planned)

---

## 🛣 Roadmap

Planned enhancements are tracked in [`TODO.md`](./TODO.md), including:

* Real-time TUI interface
* Microservice-based execution model
* Plugin system for dynamic analyzers
* Advanced fingerprinting and protocol support

---

## 👤 Author

Developed and maintained by **Jonathan**, offensive security engineer.
Zandoli is designed to be **simple, tactical, and effective** for real-world operations.

---
