# Troubleshooting

This document provides solutions to common issues encountered when using Zandoli.

## Common Issues and Solutions

### PCAP File Issues

#### Corrupt PCAP Files
**Symptoms:**
- Error: "Failed to open PCAP file"
- Error: "Invalid PCAP header"
- Scan completes but shows 0 hosts

**Solutions:**
```bash
# Verify PCAP file integrity
file traffic.pcap
# Should show: traffic.pcap: tcpdump capture file

# Check file size
ls -lh traffic.pcap
# Should be > 0 bytes

# Try with a different PCAP file
zandoli --pcap known_good.pcap --formats json

# Use tcpdump to verify PCAP
tcpdump -r traffic.pcap -c 10
```

#### Multi-Section PCAP-NG Files
**Symptoms:**
- Error: "Unsupported PCAP format"
- Incomplete packet processing

**Solutions:**
```bash
# Convert PCAP-NG to standard PCAP
editcap -F libpcap traffic.pcapng traffic.pcap

# Use tshark to convert
tshark -r traffic.pcapng -w traffic.pcap

# Check PCAP format
capinfos traffic.pcap
```

#### Empty PCAP Files
**Symptoms:**
- Scan completes successfully but no hosts discovered
- Log shows "0 packets processed"

**Solutions:**
```bash
# Verify PCAP has packets
capinfos traffic.pcap
# Check packet count > 0

# Check packet types
tcpdump -r traffic.pcap -c 10
# Look for ARP, DHCP, or other relevant protocols

# Try with a known good PCAP
zandoli --pcap testdata/sample.pcap --formats json
```

### Network Interface Issues

#### Permission Denied
**Symptoms:**
- Error: "Permission denied for interface eth0"
- Error: "Operation not permitted"

**Solutions:**
```bash
# Run with sudo for live capture
sudo zandoli --passive --interface eth0

# Or grant capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin+ep zandoli

# Check interface permissions
ls -la /sys/class/net/eth0/
```

#### Interface Not Found
**Symptoms:**
- Error: "Interface eth0 not found"
- Error: "No such device"

**Solutions:**
```bash
# List available interfaces
ip link show
# or
ifconfig -a

# Use correct interface name
zandoli --passive --interface enp0s3

# Check interface is up
ip link set eth0 up
```

#### Interface Not Supporting Capture
**Symptoms:**
- Error: "Interface does not support packet capture"
- Error: "No such file or directory"

**Solutions:**
```bash
# Check if interface supports promiscuous mode
ethtool -i eth0 | grep driver

# Try different interface
zandoli --passive --interface wlan0

# Check for virtual interfaces
ip link show type bridge
ip link show type vlan
```

### Missing ARP Data

#### No ARP Packets in Capture
**Symptoms:**
- L2 protocols not attached to hosts
- Error: "No ARP data found for MAC correlation"

**Solutions:**
```bash
# Ensure ARP traffic is present
tcpdump -i eth0 -c 10 arp

# Use combined mode for ARP scanning
zandoli --combined --passive-duration 60 --interface eth0

# Check ARP table
arp -a

# Force ARP requests
ping -c 1 192.168.1.1
```

#### Insufficient ARP Data
**Symptoms:**
- Partial host discovery
- Some hosts missing IP addresses

**Solutions:**
```bash
# Increase passive duration
zandoli --passive --passive-duration 300 --interface eth0

# Use active ARP scanning
zandoli --active --interface eth0

# Check for ARP storms (too much traffic)
zandoli --passive --verbose --interface eth0
```

### CSV Delimiter Issues

#### Excel Import Problems
**Symptoms:**
- CSV data appears in single column
- Semicolon delimiter not recognized

**Solutions:**
```bash
# Zandoli uses semicolon (;) delimiter by default
# For Excel import:
# 1. Open Excel
# 2. Data → Get Data → From Text/CSV
# 3. Select the CSV file
# 4. Set delimiter to "Semicolon"
# 5. Set encoding to UTF-8

# For LibreOffice:
# 1. File → Open
# 2. Select CSV file
# 3. Set separator to "Semicolon"
# 4. Set encoding to UTF-8
```

#### Custom Delimiter Requirements
**Symptoms:**
- Need comma delimiter for other tools
- Integration with existing systems

**Solutions:**
```bash
# Convert semicolon to comma delimiter
sed 's/;/,/g' hosts.csv > hosts_comma.csv

# Use awk for conversion
awk 'BEGIN{FS=";";OFS=","} {print $1,$2,$3,$4,$5,$6,$7,$8,$9}' hosts.csv > hosts_comma.csv
```

### Encoding Issues

#### UTF-8 Character Problems
**Symptoms:**
- Special characters not displaying correctly
- Vendor names with accents corrupted

**Solutions:**
```bash
# Ensure UTF-8 encoding
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Check file encoding
file -bi hosts.csv
# Should show: text/plain; charset=utf-8

# Convert to UTF-8 if needed
iconv -f ISO-8859-1 -t UTF-8 hosts.csv > hosts_utf8.csv
```

### Invalid Function Signature Errors

#### "Invalid function signature for limitIPsDisplay"
**Symptoms:**
- Error during HTML generation
- Template execution failure

**Solutions:**
```bash
# This is typically a template function signature mismatch
# Check Go version compatibility
go version
# Should be Go 1.18 or later

# Rebuild the binary
go clean -cache
go build -o zandoli cmd/zandoli/main.go

# Try with different export formats
zandoli --pcap traffic.pcap --formats json,csv
```

### File Permission Issues

#### Cannot Create Output Directory
**Symptoms:**
- Error: "Failed to create output directory"
- Permission denied for output files

**Solutions:**
```bash
# Check current directory permissions
ls -la .

# Create output directory manually
mkdir -p output
chmod 755 output

# Run with appropriate permissions
sudo zandoli --pcap traffic.pcap --output-dir /tmp/results
```

#### Cannot Write Log Files
**Symptoms:**
- Error: "Failed to create log file"
- Logging disabled

**Solutions:**
```bash
# Check log file permissions
ls -la output/log.txt

# Fix permissions
chmod 644 output/log.txt
chown $USER:$USER output/log.txt

# Use different output directory
zandoli --pcap traffic.pcap --output-dir /tmp/zandoli
```

## Network-Specific Issues

### Why Infrastructure Devices Show as Client/Server

#### Issue
Network devices (switches, routers) appear with client or server roles instead of "reseau" (network).

#### Causes and Solutions

**Missing L2 Protocols:**
```bash
# Check if CDP/LLDP is enabled on devices
# Enable CDP on Cisco devices:
# (config)# cdp run
# (config-if)# cdp enable

# Enable LLDP on other devices:
# (config)# lldp run
# (config-if)# lldp transmit
# (config-if)# lldp receive
```

**OUI Fallback Not Working:**
```bash
# Check OUI file is loaded
zandoli --oui-file /path/to/oui.txt --pcap traffic.pcap

# Verify OUI file format
head -5 /path/to/oui.txt
# Should show: 00:00:00   (base 16)		XEROX CORPORATION

# Check vendor detection in logs
zandoli --verbose --pcap traffic.pcap | grep "OUI lookup"
```

**Insufficient Capture Time:**
```bash
# Increase passive duration for L2 protocol capture
zandoli --passive --passive-duration 300 --interface eth0

# L2 protocols are sent periodically (every 60-180 seconds)
# Ensure capture time covers at least one cycle
```

### Private vs Public IP Detection

#### Issue
Public IP addresses appearing in private network scans.

#### Solutions
```bash
# Use blacklist to exclude public IPs
zandoli --blacklist "8.8.8.8,1.1.1.1" --pcap traffic.pcap

# Check for NAT/Proxy traffic
zandoli --verbose --pcap traffic.pcap | grep "public IP"

# Filter by subnet in post-processing
zandoli --pcap traffic.pcap --formats json
# Then filter JSON output for RFC1918 ranges only
```

### Subnet Aggregation Pitfalls

#### Issue
Subnet information incomplete or incorrect.

#### Solutions
```bash
# Ensure sufficient DHCP traffic
tcpdump -r traffic.pcap -c 20 dhcp

# Check for multiple DHCP servers
zandoli --verbose --pcap traffic.pcap | grep "DHCP"

# Use combined mode for better subnet detection
zandoli --combined --passive-duration 120 --interface eth0
```

## Diagnosing "Empty" or "Misleading" L2 Details

### Checklist for L2 Details Issues

#### 1. Verify L2 Protocol Presence
```bash
# Check for CDP packets
tcpdump -r traffic.pcap -c 10 -v | grep -i cdp

# Check for LLDP packets  
tcpdump -r traffic.pcap -c 10 -v | grep -i lldp

# Check for STP packets
tcpdump -r traffic.pcap -c 10 -v | grep -i stp
```

#### 2. Verify Packet Parsing
```bash
# Enable verbose logging
zandoli --verbose --pcap traffic.pcap | grep -E "(CDP|LLDP|STP)"

# Check for parsing errors
zandoli --verbose --pcap traffic.pcap | grep "ERR"
```

#### 3. Verify MAC↔IP Correlation
```bash
# Check ARP data
tcpdump -r traffic.pcap -c 20 arp

# Verify correlation in logs
zandoli --verbose --pcap traffic.pcap | grep "MAC correlation"
```

#### 4. Check VLAN Information
```bash
# Verify 802.1Q tags
tcpdump -r traffic.pcap -c 10 -v | grep "vlan"

# Check VLAN detection
zandoli --verbose --pcap traffic.pcap | grep "VLAN"
```

### Common L2 Details Problems

#### No L2 Details Despite Protocols Present
**Cause:** MAC↔IP correlation failed
**Solution:** Ensure ARP data is present for correlation

#### Incomplete CDP/LLDP Information
**Cause:** Insufficient capture time
**Solution:** Increase passive duration to capture complete protocol exchange

#### Missing VLAN Information
**Cause:** No 802.1Q tagged traffic
**Solution:** Ensure VLAN traffic is present in capture

## Performance Issues

### Large PCAP Processing

#### Memory Issues
**Symptoms:**
- Out of memory errors
- System slowdown during processing

**Solutions:**
```bash
# Use streaming mode for large files
zandoli --pcap large_file.pcap --formats json

# Process in chunks
split -l 10000 large_file.pcap chunk_
for file in chunk_*; do
    zandoli --pcap "$file" --formats json --output-dir "results_$file"
done
```

#### Slow Processing
**Symptoms:**
- Very slow PCAP processing
- High CPU usage

**Solutions:**
```bash
# Check system resources
top
htop

# Use fewer output formats
zandoli --pcap traffic.pcap --formats json

# Process on faster system
# Consider using SSD storage for temporary files
```

### Network Impact

#### High Network Load
**Symptoms:**
- Network slowdown during active scanning
- Complaints from network users

**Solutions:**
```bash
# Use stealth mode
zandoli --active --stealth --interface eth0

# Reduce scan rate
zandoli --active --arp-max-per-sec 1 --arp-burst 5

# Use blacklist to exclude sensitive networks
zandoli --blacklist "192.168.1.0/24" --active
```

## Debugging Commands

### Useful Debugging Commands

#### Check System Information
```bash
# Check Go version
go version

# Check system resources
free -h
df -h

# Check network interfaces
ip link show
```

#### Verify PCAP Content
```bash
# Check PCAP file information
capinfos traffic.pcap

# List packet types
tcpdump -r traffic.pcap -c 100 | cut -d' ' -f5 | sort | uniq -c

# Check for specific protocols
tcpdump -r traffic.pcap -c 10 arp
tcpdump -r traffic.pcap -c 10 dhcp
tcpdump -r traffic.pcap -c 10 -v | grep -i cdp
```

#### Test with Known Data
```bash
# Use test data
zandoli --pcap testdata/sample.pcap --formats json

# Generate test traffic
ping -c 10 192.168.1.1
zandoli --passive --passive-duration 30 --interface eth0
```

## Getting Help

### Log Analysis
```bash
# Enable verbose logging for debugging
zandoli --verbose --pcap traffic.pcap > debug.log 2>&1

# Analyze logs for errors
grep -E "(ERR|WARN)" debug.log

# Check for specific issues
grep -E "(packet|host|role)" debug.log
```

### Community Support
- Check GitHub issues for similar problems
- Provide detailed logs when reporting issues
- Include system information and Go version
- Provide sample PCAP files when possible

## See Also

- [CLI Reference](CLI.md)
- [Logging](LOGGING.md)
- [Layer 2 Protocols](L2_PROTOCOLS.md)
- [Security Considerations](SECURITY.md)
