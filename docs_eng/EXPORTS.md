# Export Formats

This document describes the various export formats supported by Zandoli and their specific characteristics.

## Supported Formats

Zandoli supports multiple export formats to accommodate different use cases:

- **HTML**: Interactive web-based reports
- **CSV**: Tabular data for spreadsheet applications
- **JSON**: Machine-readable structured data
- **Markdown**: Human-readable documentation format
- **XML**: Structured data for enterprise integration

## HTML Export

### Features

The HTML export provides a comprehensive, interactive web interface:

- **Interactive filtering** by role (client, server, network)
- **Search functionality** across IPs, MACs, vendors, and roles
- **Responsive design** for desktop and mobile viewing
- **Network topology visualization**
- **Subnet analysis** with RFC1918 classification
- **Layer 2 protocol details** with expandable sections
- **Anomaly highlighting** with severity indicators

### Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Zandoli Network Recon Report</title>
    <style>/* Modern CSS styling */</style>
</head>
<body>
    <header>Report header with logo and title</header>
    <main>
        <div class="stats-grid">Global statistics</div>
        <div class="section">Global summary</div>
        <div class="section">Host discovery table</div>
        <div class="section">Subnet analysis</div>
    </main>
    <script>/* Interactive JavaScript */</script>
</body>
</html>
```

### Interactive Features

#### Filtering and Search
- **Role Filter Tabs**: Filter hosts by client/server/network roles
- **Search Box**: Real-time search across host data
- **Subnet Filtering**: Click subnet links to filter by network range

#### Data Presentation
- **Expandable Details**: Layer 2 protocol information
- **Tooltips**: Additional information on hover
- **Badge System**: Visual indicators for protocols and roles
- **Color Coding**: Severity levels for anomalies

### Sample HTML Output

```html
<div class="section">
  <h2>🖥️ Hôtes Découverts</h2>
  <input type="text" class="search-box" placeholder="Rechercher un hôte...">
  <div class="filter-tabs">
    <button class="filter-tab active">Tous</button>
    <button class="filter-tab">Clients</button>
    <button class="filter-tab">Serveurs</button>
    <button class="filter-tab">Réseaux</button>
  </div>
  <table id="hostsTable">
    <thead>
      <tr>
        <th>IP (IPv4)</th>
        <th>IPv6</th>
        <th>MAC</th>
        <th>Constructeur</th>
        <th>Rôle</th>
        <th>TTL</th>
        <th>OS (Score)</th>
        <th>Ports</th>
        <th>Protocoles</th>
        <th>Détails L2</th>
        <th>VLAN</th>
      </tr>
    </thead>
    <tbody>
      <!-- Host rows with interactive features -->
    </tbody>
  </table>
</div>
```

## CSV Export

### Format Specification

The CSV export uses **semicolon (`;`) as the delimiter** for better compatibility with European locale Excel and LibreOffice installations.

### Column Structure

| Column | Description | Example |
|--------|-------------|---------|
| MAC | MAC address | `00:11:22:33:44:55` |
| Vendor | Device vendor | `Cisco Systems` |
| VLANs | Observed VLANs | `1,10,20` |
| L2Flags | Layer 2 protocol flags | `CDP,STP` |
| IP | Primary IPv4 address | `192.168.1.100` |
| IPv6 | Primary IPv6 address | `2001:db8::1` |
| UDP_Services | UDP ports | `53,161,162` |
| TCP_Services | TCP ports | `22,23,80,443` |
| Protocols | Observed protocols | `CDP,STP,ARP,DHCP` |

### Sample CSV Output

```csv
MAC;Vendor;VLANs;L2Flags;IP;IPv6;UDP_Services;TCP_Services;Protocols
00:11:22:33:44:55;Cisco Systems;1,10,20;CDP,STP;192.168.1.100;2001:db8::1;53,161,162;22,23,80,443;CDP,STP,ARP,DHCP
00:aa:bb:cc:dd:ee;Hewlett Packard;1,100;LLDP;192.168.1.101;;;80,443;LLDP,ARP,HTTP
```

### Excel/LibreOffice Tips

1. **Import Settings**: Use semicolon as delimiter
2. **Text Encoding**: Use UTF-8 encoding
3. **Data Types**: Import MAC addresses as text to preserve formatting
4. **Filtering**: Use auto-filter for data analysis

## JSON Export

### Schema Overview

The JSON export provides a complete, machine-readable representation of the scan results:

```json
{
  "version": "1",
  "generatedAt": "2024-01-15T12:45:00Z",
  "count": 25,
  "hosts": [
    {
      "ip": "192.168.1.100",
      "ipv6": "2001:db8::1",
      "macStr": "00:11:22:33:44:55",
      "vendor": "Cisco Systems",
      "role": "reseau",
      "roleConfidence": 100,
      "roleSignals": ["L2_PRESENT"],
      "protocols": ["CDP", "STP", "ARP"],
      "cdp": {
        "device_id": "switch-01",
        "platform": "WS-C2960-24TC-L",
        "version": "C2960 Software, Version 12.2(55)SE7"
      },
      "l2": {
        "vlans": [1, 10, 20],
        "cdp": true,
        "stp": true
      },
      "services": {
        "tcp": [22, 23, 80, 443],
        "udp": [53, 161, 162]
      },
      "anomalies": []
    }
  ],
  "subnets": [
    {
      "cidr": "192.168.1.0/24",
      "source": "dhcp",
      "countHosts": 15,
      "vlans": [1, 10, 20]
    }
  ],
  "topology": {
    "subnets": [
      {
        "cidr": "192.168.1.0/24",
        "version": "ipv4",
        "source": "dhcp",
        "hostsCount": 15,
        "ipSamples": ["192.168.1.1", "192.168.1.10", "192.168.1.100"]
      }
    ]
  }
}
```

### Field Meanings

#### Host Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | Primary IPv4 address |
| `ipv6` | string | Primary IPv6 address |
| `macStr` | string | MAC address in string format |
| `vendor` | string | Device vendor from OUI lookup |
| `role` | string | Inferred role: "client", "server", "reseau" |
| `roleConfidence` | integer | Confidence score 0-100 |
| `roleSignals` | array | Signals used for role inference |
| `protocols` | array | Observed network protocols |
| `cdp` | object | CDP protocol details |
| `lldp` | object | LLDP protocol details |
| `stp` | object | STP protocol details |
| `l2` | object | Layer 2 signals summary |
| `services` | object | TCP/UDP services |
| `anomalies` | array | Detected anomalies |

#### Anomaly Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Anomaly type identifier |
| `severity` | string | "low", "medium", "high" |
| `key` | string | Deduplication key |
| `scope` | string | "global" or "vlan:<id>" |
| `description` | string | Human-readable description |
| `parameters` | object | Type-specific parameters |

## Markdown Export

### Format Structure

The Markdown export provides a human-readable documentation format:

```markdown
# Zandoli Network Reconnaissance Report

**Generated:** 2024-01-15 12:45:00  
**Version:** v0.94  
**Total Hosts:** 25

## Summary

- **Vendors:** Cisco Systems (5), Hewlett Packard (3), Dell (2)
- **Roles:** Network (8), Server (12), Client (5)
- **Protocols:** ARP (25), DHCP (15), CDP (5), LLDP (3)

## Host Details

| IP | MAC | Vendor | Role | Protocols | L2 Details |
|----|-----|--------|------|-----------|------------|
| 192.168.1.100 | 00:11:22:33:44:55 | Cisco Systems | Network | CDP,STP,ARP | CDP: switch-01, WS-C2960 |

## Subnets

### RFC 1918 Private Networks

#### Class A (10.0.0.0/8)
- 10.0.0.0/24 (5 hosts)

#### Class B (172.16.0.0/12)
- 172.16.1.0/24 (8 hosts)

#### Class C (192.168.0.0/16)
- 192.168.1.0/24 (12 hosts)
```

### Features

- **Structured sections** with clear headings
- **Tables** for host and subnet data
- **Code blocks** for technical details
- **Lists** for summary information
- **Compatible** with GitHub, GitLab, and documentation systems

## XML Export

### Schema Structure

The XML export provides structured data for enterprise integration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<zandoli-report version="1" generatedAt="2024-01-15T12:45:00Z">
  <summary>
    <totalHosts>25</totalHosts>
    <totalSubnets>3</totalSubnets>
    <scanDuration>120</scanDuration>
  </summary>
  
  <hosts>
    <host>
      <ip>192.168.1.100</ip>
      <ipv6>2001:db8::1</ipv6>
      <mac>00:11:22:33:44:55</mac>
      <vendor>Cisco Systems</vendor>
      <role confidence="100">reseau</role>
      <protocols>
        <protocol>CDP</protocol>
        <protocol>STP</protocol>
        <protocol>ARP</protocol>
      </protocols>
      <l2-details>
        <cdp>
          <device-id>switch-01</device-id>
          <platform>WS-C2960-24TC-L</platform>
          <version>C2960 Software, Version 12.2(55)SE7</version>
        </cdp>
      </l2-details>
      <services>
        <tcp>22,23,80,443</tcp>
        <udp>53,161,162</udp>
      </services>
    </host>
  </hosts>
  
  <subnets>
    <subnet cidr="192.168.1.0/24" source="dhcp" hostCount="15">
      <vlans>1,10,20</vlans>
      <samples>192.168.1.1,192.168.1.10,192.168.1.100</samples>
    </subnet>
  </subnets>
</zandoli-report>
```

### Features

- **Namespace support** for extensibility
- **Attribute-based** metadata storage
- **Hierarchical structure** for complex data
- **Schema validation** support
- **Enterprise integration** ready

## Output Directory Structure

### Default Layout

```
output/
├── scan_20240115-124500/
│   ├── hosts.html          # HTML report
│   ├── hosts.csv           # CSV export
│   ├── hosts.json          # JSON export
│   ├── hosts.md            # Markdown export
│   ├── hosts.xml           # XML export
│   └── log.txt             # Scan log
└── log.txt                 # Global log
```

### Custom Output Directory

```bash
# Specify custom output directory
./zandoli --pcap traffic.pcap --output-dir /path/to/results --formats html,json
```

Results will be saved to:
```
/path/to/results/
└── scan_20240115-124500/
    ├── hosts.html
    ├── hosts.json
    └── log.txt
```

## Format Selection

### Command Line Usage

```bash
# Single format
./zandoli --pcap traffic.pcap --formats html

# Multiple formats
./zandoli --pcap traffic.pcap --formats html,csv,json

# All formats
./zandoli --pcap traffic.pcap --formats html,csv,json,markdown,xml
```

### Configuration File

```yaml
output:
  formats: ["html", "csv", "json"]
```

## Data Consistency

### Cross-Format Consistency

All export formats contain the same core data:

- **Host information** is identical across formats
- **Layer 2 details** are preserved in all formats
- **Anomaly information** is consistently represented
- **Subnet data** maintains the same structure

### Format-Specific Enhancements

Each format adds format-specific features:

- **HTML**: Interactive features and styling
- **CSV**: Tabular structure for analysis
- **JSON**: Machine-readable structure
- **Markdown**: Documentation formatting
- **XML**: Enterprise integration structure

## Performance Considerations

### Large Dataset Handling

- **Streaming exports** for large host lists
- **Memory-efficient** processing
- **Progressive rendering** for HTML reports
- **Chunked processing** for CSV/JSON exports

### File Size Optimization

- **Compression support** for large files
- **Selective export** of relevant data
- **Efficient encoding** for all formats
- **Minimized redundancy** across formats

## See Also

- [CLI Reference](CLI.md)
- [Data Model](DATA_MODEL.md)
- [Architecture Overview](ARCHITECTURE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
