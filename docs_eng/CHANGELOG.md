# Changelog

All notable changes to Zandoli are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive English documentation set
- Interactive HTML reports with filtering and search
- CSV export with semicolon delimiter for Excel compatibility
- JSON export with complete data structures
- Markdown and XML export formats
- Dual-stack IPv4/IPv6 support
- VLAN-aware network topology
- Anomaly detection and reporting
- Role inference with confidence scoring
- Stealth scanning modes
- Rate limiting and burst control

### Changed
- CSV delimiter changed from comma to semicolon for better international compatibility
- Enhanced Layer 2 protocol details in reports
- Improved MAC↔IP correlation algorithms
- Optimized memory usage for large PCAP files
- Updated role inference priority matrix

### Fixed
- Memory leaks in large PCAP processing
- Race conditions in concurrent packet processing
- Invalid function signature errors in HTML templates
- CSV injection vulnerabilities
- Encoding issues with special characters

## [0.94] - 2024-01-15

### Added
- **Layer 2 Protocol Support**
  - CDP (Cisco Discovery Protocol) parsing with TLV extraction
  - LLDP (Link Layer Discovery Protocol) parsing with TLV extraction
  - STP (Spanning Tree Protocol) BPDU analysis
  - 802.1X (EAPOL) detection

- **Enhanced Role Inference**
  - L2 protocol priority (100% confidence for network devices)
  - OUI vendor classification (90% confidence)
  - Behavioral analysis for client/server detection
  - Confidence scoring (0-100%) for all role assignments

- **Network Topology Features**
  - VLAN-aware subnet discovery
  - RFC1918 private network classification
  - IPv4/IPv6 dual-stack support
  - Subnet aggregation and deduplication

- **Anomaly Detection**
  - ARP storm detection
  - Multiple IPs per MAC detection
  - Duplicate IP address detection
  - Duplicate hostname detection
  - Suspicious TTL pattern detection

- **Export Formats**
  - HTML reports with interactive features
  - CSV export with semicolon delimiter
  - JSON export with complete data structures
  - Markdown documentation format
  - XML export for enterprise integration

### Changed
- **CSV Format**: Changed delimiter from comma to semicolon for better Excel/LibreOffice compatibility
- **HTML Reports**: Enhanced with filtering, search, and interactive features
- **Role Inference**: Improved priority matrix with L2 protocols taking absolute precedence
- **MAC↔IP Correlation**: Enhanced with strength assessment and conflict resolution
- **Subnet Discovery**: Improved with VLAN awareness and hierarchical display

### Fixed
- **Memory Management**: Fixed memory leaks in large PCAP processing
- **Concurrency**: Resolved race conditions in packet processing
- **Template Errors**: Fixed invalid function signature errors in HTML templates
- **CSV Security**: Prevented CSV injection attacks with proper delimiter handling
- **Encoding**: Fixed UTF-8 character encoding issues in exports

### Security
- **Input Validation**: Enhanced validation for all user inputs
- **CSV Injection**: Prevented CSV injection attacks with semicolon delimiter
- **Error Handling**: Improved error handling without exposing sensitive information
- **Log Sanitization**: Added options for log data anonymization

## [0.93] - 2024-01-01

### Added
- Basic PCAP file analysis
- ARP and DHCP protocol parsing
- Simple host discovery
- Basic CSV export
- Configuration file support

### Changed
- Initial release with core functionality
- Basic role inference (client/server)
- Simple network discovery

### Fixed
- Initial bug fixes and stability improvements

## [0.92] - 2023-12-15

### Added
- Initial project structure
- Basic packet capture functionality
- Simple protocol parsing
- Basic data structures

### Changed
- Project initialization
- Core architecture design
- Initial implementation

## Migration Guide

### From 0.93 to 0.94

#### CSV Format Changes
The CSV delimiter has changed from comma to semicolon. Update your import scripts:

```bash
# Old format (comma-delimited)
# IP,MAC,Vendor,Role

# New format (semicolon-delimited)
# IP;MAC;Vendor;Role
```

#### Configuration Changes
New configuration options have been added:

```yaml
# New options in config.yaml
scan:
  stealth: false                    # Enable stealth mode
  arp_max_per_sec: 3               # ARP rate limiting
  arp_burst: 10                    # ARP burst size
  burst_min_delay_ms: 100          # Burst delay
  burst_max_delay_ms: 500          # Maximum burst delay

output:
  formats: ["json", "csv", "html"] # Export formats
  allow_public_subnets: false      # Include public subnets
```

#### CLI Changes
New command-line options:

```bash
# New flags
--stealth                    # Enable stealth mode
--arp-max-per-sec <n>       # ARP rate limiting
--arp-burst <n>             # ARP burst size
--burst-min-delay <ms>      # Burst delay
--burst-max-delay <ms>      # Maximum burst delay
--formats <f1,f2>           # Export formats
--blacklist <ip1,ip2>       # IP/subnet exclusion
```

#### Data Model Changes
The data model has been enhanced with new fields:

```json
{
  "ipv6": "2001:db8::1",           // New: IPv6 primary address
  "roleConfidence": 90,            // New: Role confidence score
  "roleSignals": ["L2_PRESENT"],   // New: Role inference signals
  "cdp": { /* CDP data */ },       // New: CDP protocol details
  "lldp": { /* LLDP data */ },     // New: LLDP protocol details
  "stp": { /* STP data */ },       // New: STP protocol details
  "l2": {                         // New: L2 signals summary
    "vlans": [1, 10, 20],
    "cdp": true,
    "stp": true
  },
  "anomalies": [ /* anomalies */ ] // New: Anomaly detection
}
```

## Breaking Changes

### 0.94
- **CSV Delimiter**: Changed from comma to semicolon (may break existing import scripts)
- **Configuration Format**: New required fields in configuration file
- **Data Model**: New required fields in JSON export format

### 0.93
- **Initial Release**: No breaking changes from previous versions

## Deprecations

### 0.94
- **Legacy CSV Format**: Comma-delimited CSV format is deprecated
- **Basic Role Inference**: Simple client/server detection is deprecated in favor of enhanced role inference
- **Single IP Support**: Single IP address per host is deprecated in favor of multi-IP support

## Known Issues

### 0.94
- **Large PCAP Files**: Very large PCAP files (>10GB) may cause memory issues
- **VLAN Detection**: VLAN information may be incomplete without 802.1Q tagged traffic
- **Role Inference**: Some devices may be misclassified without sufficient protocol data
- **Performance**: Active scanning may impact network performance on busy networks

### 0.93
- **Memory Usage**: Memory usage could be high for large PCAP files
- **Role Inference**: Limited role inference capabilities
- **Export Formats**: Limited export format options

## Future Plans

### Planned for 0.95
- **Performance Improvements**: Better memory management for large datasets
- **Additional Protocols**: Support for more Layer 2 protocols
- **Enhanced Anomaly Detection**: More sophisticated anomaly detection algorithms
- **Real-time Monitoring**: Live network monitoring capabilities
- **API Interface**: REST API for programmatic access

### Planned for 1.0.0
- **Stable API**: Stable API for third-party integrations
- **Plugin System**: Plugin architecture for custom protocol parsers
- **Web Interface**: Web-based user interface
- **Enterprise Features**: Advanced reporting and analytics
- **Cloud Integration**: Cloud-based scanning and reporting

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on contributing to Zandoli.

## Support

For support and bug reports, please use the GitHub issue tracker.

## License

[License information to be added]

## See Also

- [README](README.md)
- [Architecture Overview](ARCHITECTURE.md)
- [CLI Reference](CLI.md)
- [Troubleshooting](TROUBLESHOOTING.md)
