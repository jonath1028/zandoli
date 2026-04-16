# Security Considerations

This document outlines security considerations, best practices, and limitations when using Zandoli.

## Security Scope

### What Zandoli Does
- **Passive network analysis** of captured traffic
- **Active network scanning** with ARP and SYN probes
- **Protocol parsing** and device identification
- **Report generation** in multiple formats

### What Zandoli Does NOT Do
- **Network exploitation** or penetration testing
- **Vulnerability scanning** or security assessment
- **Traffic modification** or packet injection (beyond scan probes)
- **Authentication bypass** or privilege escalation
- **Data exfiltration** or unauthorized access

## Passive Analysis Security

### Read-Only Operations
Zandoli's passive analysis is inherently secure:

- **No network modification**: Only reads existing traffic
- **Local processing**: All analysis performed on the local system
- **No data transmission**: Results stay on the local machine
- **No authentication**: No credentials or keys required

### Data Handling
- **Local storage**: All data remains on the scanning system
- **No external connections**: No data sent to external services
- **Memory cleanup**: Sensitive data cleared after processing
- **File permissions**: Output files respect system permissions

## Active Scanning Security

### Controlled Impact
Active scanning is designed to minimize network disruption:

- **Rate limiting**: Configurable packet rates prevent flooding
- **Stealth modes**: Randomized timing to avoid detection
- **Blacklist support**: Exclude sensitive networks and devices
- **TTL configuration**: Control packet lifetimes

### Scan Types

#### ARP Scanning
- **Purpose**: Host discovery and MAC↔IP correlation
- **Impact**: Minimal - standard ARP requests
- **Detection**: May appear in ARP tables and logs
- **Mitigation**: Use stealth mode and rate limiting

#### SYN Scanning
- **Purpose**: Service detection on target hosts
- **Impact**: May trigger firewall alerts
- **Detection**: Visible in network monitoring tools
- **Mitigation**: Use conservative port lists and timing

## Output Security

### HTML Report Security
- **No active content**: Static HTML with JavaScript for interactivity
- **No external resources**: Self-contained report files
- **Sanitized data**: No executable code in host data
- **Safe viewing**: Can be opened in any web browser

### CSV Export Security
- **Plain text format**: No macros or executable content
- **Delimiter injection**: Semicolon delimiter prevents CSV injection
- **Safe import**: Safe for Excel, LibreOffice, and other tools
- **No formulas**: Pure data without executable formulas

### JSON Export Security
- **Structured data**: Machine-readable format without code
- **No eval() content**: Safe JSON without executable elements
- **Standard format**: Compatible with all JSON parsers
- **No external references**: Self-contained data structure

## Data Privacy and Anonymization

### Sensitive Information
Zandoli may collect sensitive network information:

- **IP addresses** of discovered hosts
- **MAC addresses** of network devices
- **Hostnames** and device identifiers
- **Network topology** and relationships
- **Protocol information** and service details

### Anonymization Options

#### Manual Anonymization
```bash
# Anonymize IP addresses in logs
sed -i 's/192\.168\.[0-9]*\.[0-9]*/XXX.XXX.XXX.XXX/g' output/log.txt

# Anonymize MAC addresses
sed -i 's/[0-9a-f:]*:\([0-9a-f][0-9a-f]\):\([0-9a-f][0-9a-f]\)/XX:XX:XX:XX:XX:\1\2/g' output/log.txt

# Anonymize hostnames
sed -i 's/hostname="[^"]*"/hostname="ANONYMIZED"/g' output/log.txt
```

#### Post-Processing Anonymization
```bash
# Anonymize JSON output
jq 'walk(if type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$") then "XXX.XXX.XXX.XXX" else . end)' hosts.json > hosts_anon.json
```

### Data Retention
- **Local storage**: Data remains on scanning system
- **No cloud upload**: No automatic data transmission
- **Manual cleanup**: User responsible for data deletion
- **Log rotation**: Manual log management required

## Network Security Considerations

### Firewall and IDS Detection
Active scanning may trigger security alerts:

- **ARP requests**: May appear in network monitoring
- **SYN probes**: Likely to trigger firewall alerts
- **Rate monitoring**: High packet rates may be flagged
- **Pattern detection**: Stealth modes help avoid detection

### Best Practices
```bash
# Use stealth mode for sensitive networks
zandoli --active --stealth --interface eth0

# Limit scan rate
zandoli --active --arp-max-per-sec 1 --arp-burst 5

# Exclude sensitive networks
zandoli --blacklist "192.168.1.0/24,10.0.0.0/8" --active

# Use conservative timing
zandoli --active --burst-min-delay 1000 --burst-max-delay 5000
```

### Network Impact Minimization
- **Off-peak scanning**: Scan during low-usage periods
- **Incremental scanning**: Scan small network segments
- **Coordination**: Inform network administrators
- **Documentation**: Maintain scan logs and justifications

## System Security

### Privilege Requirements
- **Root privileges**: Required for live packet capture
- **Network capabilities**: May need CAP_NET_RAW capability
- **File permissions**: Output directory must be writable

### Secure Installation
```bash
# Install with minimal privileges
sudo install -m 755 zandoli /usr/local/bin/

# Set capabilities instead of full root
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/zandoli

# Create dedicated user
sudo useradd -r -s /bin/false zandoli
sudo chown zandoli:zandoli /usr/local/bin/zandoli
```

### File System Security
```bash
# Secure output directory
mkdir -p /var/log/zandoli
chmod 700 /var/log/zandoli
chown zandoli:zandoli /var/log/zandoli

# Secure log files
chmod 600 /var/log/zandoli/*.log
chown zandoli:zandoli /var/log/zandoli/*.log
```

## Compliance Considerations

### Data Protection Regulations
Consider applicable regulations when collecting network data:

- **GDPR**: EU data protection regulation
- **CCPA**: California consumer privacy act
- **HIPAA**: Healthcare data protection (if applicable)
- **SOX**: Financial data protection (if applicable)

### Organizational Policies
- **Network scanning policies**: Ensure compliance with organizational rules
- **Data handling policies**: Follow data classification and handling requirements
- **Retention policies**: Comply with data retention requirements
- **Access control**: Limit access to scan results

## Threat Model

### Potential Threats

#### Information Disclosure
- **Network topology**: Reveals network structure and relationships
- **Device inventory**: Lists all network devices and services
- **Vendor information**: Reveals equipment manufacturers and models
- **Service enumeration**: Lists open ports and services

#### Network Disruption
- **Scanning traffic**: May cause network congestion
- **False alarms**: May trigger security alerts
- **Resource consumption**: May impact network performance
- **Log flooding**: May fill up log files

### Mitigation Strategies

#### Information Disclosure Mitigation
- **Access control**: Limit access to scan results
- **Data classification**: Treat results as sensitive information
- **Secure storage**: Encrypt scan results if required
- **Need-to-know**: Share results only with authorized personnel

#### Network Disruption Mitigation
- **Rate limiting**: Use conservative scan rates
- **Stealth modes**: Minimize detection and impact
- **Coordination**: Inform network administrators
- **Testing**: Test scans in isolated environments first

## Secure Usage Guidelines

### Pre-Scan Checklist
- [ ] Verify authorization for network scanning
- [ ] Confirm scan scope and timing
- [ ] Check for sensitive networks to exclude
- [ ] Ensure proper system permissions
- [ ] Plan for secure result storage

### During Scan
- [ ] Monitor network impact
- [ ] Watch for security alerts
- [ ] Document any issues
- [ ] Maintain scan logs
- [ ] Respect rate limits

### Post-Scan
- [ ] Secure scan results
- [ ] Clean up temporary files
- [ ] Archive logs securely
- [ ] Share results appropriately
- [ ] Document findings

## Incident Response

### Security Incident Handling
If security issues arise during scanning:

1. **Stop scanning immediately**
2. **Document the incident**
3. **Notify relevant personnel**
4. **Preserve evidence**
5. **Follow incident response procedures**

### Common Incidents
- **Network disruption**: Stop scan and assess impact
- **Security alerts**: Document and report to security team
- **Unauthorized access**: Secure system and investigate
- **Data breach**: Follow data breach response procedures

## Security Testing

### Penetration Testing Considerations
Zandoli is not a penetration testing tool, but may be used in security assessments:

- **Network discovery**: Identify network devices and services
- **Asset inventory**: Catalog network assets
- **Topology mapping**: Understand network structure
- **Baseline establishment**: Create security baselines

### Limitations
- **No vulnerability assessment**: Does not identify security vulnerabilities
- **No exploitation**: Does not attempt to exploit discovered services
- **No privilege escalation**: Does not attempt to gain unauthorized access
- **No data exfiltration**: Does not attempt to steal or modify data

## Best Practices Summary

### Operational Security
1. **Authorize all scanning activities**
2. **Use appropriate scan modes and timing**
3. **Respect network resources and policies**
4. **Secure scan results and logs**
5. **Follow data handling procedures**

### Technical Security
1. **Use stealth modes when appropriate**
2. **Implement rate limiting and blacklists**
3. **Secure system and file permissions**
4. **Monitor for security alerts**
5. **Maintain secure configurations**

### Organizational Security
1. **Establish scanning policies**
2. **Train operators on security procedures**
3. **Implement access controls**
4. **Maintain audit trails**
5. **Regular security reviews**

## See Also

- [CLI Reference](CLI.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Logging](LOGGING.md)
- [Architecture Overview](ARCHITECTURE.md)
