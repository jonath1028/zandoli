# Zandoli – Stealth Internal Network Reconnaissance

Zandoli is a stealth-focused internal reconnaissance tool developed in Go for penetration testers operating in monitored corporate environments. It answers the need for discreet asset discovery by combining passive sniffing and active ARP scanning, enabling early-phase infrastructure mapping without triggering detection. Designed to run on Linux jumpboxes or analyst machines, it is best suited for use during internal assessments or when analyzing offline packet captures.

---

## 🔧 Core Features

- **Passive Reconnaissance**
  - Captures LLDP, ARP, DHCP, EAPOL, and VLAN traffic
  - Zero packet injection; no interaction with hosts

- **Active ARP Scanning**
  - Unicast probing in jittered, rate-limited bursts
  - Normal and stealth modes

- **Host Classification**
  - MAC OUI lookup for vendor inference
  - Auto-categorization of hosts

- **Anomaly Detection**
  - Detects IP/MAC inconsistencies and duplicate assets

- **Offline Analysis**
  - Full `.pcap` support for post-capture inspection

- **Structured Export**
  - JSON, CSV and static HTML reports

- **Hardened Runtime**
  - Graceful SIGINT handling, timeout support, interface validation

---

## 🎯 Use Cases for Pentesters

- Discreetly map internal subnets during on-site or VPN-based engagements
- Perform reconnaissance from a jumpbox or compromised workstation without triggering EDR or NAC alerts
- Leverage `.pcap` files for passive post-exploitation infrastructure mapping
- Validate network segmentation and identify unmanaged or rogue devices
- Identify asset density and device types within poorly segmented VLANs

---

## 📊 Recon Workflow

```
[ Interface Setup ]
        ↓
[ Passive Capture ]
        ↓
[ Active ARP Scan (Optional) ]
        ↓
[ Packet Analysis ]
        ↓
[ Host Classification ]
        ↓
[ Anomaly Detection ]
        ↓
[ Report Generation ]
        ↓
[ Export to JSON / CSV / HTML ]
```

---

## 🚀 Quickstart

### 📦 Installation

```bash
git clone https://github.com/jonath1028/zandoli.git
cd zandoli
chmod +x install.sh
sudo ./install.sh
```

### ⚙️ Sample Commands

```bash
# Passive only
sudo ./zandoli --mode passive --config assets/config.yaml

# Stealth ARP only
sudo ./zandoli --mode active --config assets/config.yaml

# Combined scan
sudo ./zandoli --mode combined --config assets/config.yaml

# Offline pcap analysis
sudo ./zandoli --mode pcap --file capture.pcap --config assets/config.yaml

# Display help
./zandoli -h
```

---

## 🧬 Configuration Variables

**Path:** `assets/config.yaml`

| Variable                    | Description                                         | Example               |
|-----------------------------|-----------------------------------------------------|------------------------|
| `iface`                     | Interface to use                                    | `eth0`                |
| `log_level`                 | Logging verbosity (`debug`, `info`, `warn`, ...)    | `info`                |
| `log_file`                  | Log output file path                                | `output/log.txt`      |
| `output_dir`                | Output directory for results                        | `output/`             |
| `oui_path`                  | Path to OUI vendor database                         | `assets/oui.txt`      |
| `stealth_arp.jitter_min`    | Min delay between ARP packets (ms)                 | `55000`               |
| `stealth_arp.jitter_max`    | Max delay between ARP packets (ms)                 | `95000`               |
| `stealth_arp.burst_rate`    | Max ARP packets per burst                           | `3`                   |
| `stealth_arp.burst_window`  | Time window per burst (sec)                         | `25`                  |

---

## 📁 Project Structure

```
├── cmd/                 → CLI entrypoint
├── pkg/
│   ├── analyzer/        → Protocol-specific analyzers (LLDP, ARP, ...)
│   ├── scanner/         → Active scanners (ARP)
│   ├── sniffer/         → Passive packet capture
│   └── utils/           → Shared logic and helpers
├── assets/              → Config file, oui.txt
├── output/              → Generated results
├── script/              → Auxiliary tools (OUI processing, etc.)
└── install.sh           → Dependency setup and build script
```

---

## 📈 Roadmap

- [ ] **Semi-passive OS fingerprinting** using controlled SYN packets
- [ ] **Passive protocol enrichment** (extract hostnames, domains, NBNS, DHCP options)
- [ ] **Enhanced passive heuristics** to infer device types and operating roles
- [ ] **Vendor classification enrichment**
- [ ] **Plugin support for new protocol analyzers**
- [ ] **Memory optimizations using circular buffers**

---

## ⚖️ License & Disclaimer

Zandoli is intended strictly for legal use in authorized environments.  
Unauthorized use is prohibited. The authors accept no responsibility for misuse.

---

## 🤝 Contributions

Pull requests are welcome. All contributions must comply with the project’s modular architecture, interface segregation, and security guidelines.
