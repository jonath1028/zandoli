# Logging

This document describes Zandoli's logging system, configuration options, and log file management.

## Logging Overview

Zandoli uses structured logging with multiple output destinations and configurable verbosity levels. The logging system is built on the zerolog library and provides both console and file output.

## Log Destinations

### File Output
- **Global log**: `output/log.txt` (append mode)
- **Scan-specific log**: `output/scan_TIMESTAMP/log.txt`
- **Log format**: Timestamp, level, message, context fields

### Console Output
- **Default**: No console output (paranoid mode)
- **Verbose mode**: Detailed information to stdout
- **Quiet mode**: Minimal output to stdout
- **Normal mode**: Essential information only

## Log Levels

### Available Levels

| Level | Description | Usage |
|-------|-------------|-------|
| **TRACE** | Most detailed information | Development and debugging |
| **DEBUG** | Detailed diagnostic information | Troubleshooting |
| **INFO** | General information about operation | Normal operation |
| **WARN** | Warning messages for potential issues | Non-critical problems |
| **ERROR** | Error messages for failures | Critical problems |

### Log Level Configuration

Log levels are controlled by the logging mode flags:

```bash
# Verbose mode - DEBUG level and above
zandoli --verbose --pcap traffic.pcap

# Quiet mode - WARN level and above
zandoli --quiet --passive --passive-duration 60

# Paranoid mode - No console output, file only
zandoli --paranoid --passive --passive-duration 60

# Normal mode - INFO level and above (default)
zandoli --pcap traffic.pcap
```

## Log Format

### Standard Log Format

```
2024-01-15T12:45:30.123456Z INF Zandoli scan started interface=eth0 mode=passive
2024-01-15T12:45:30.124567Z DBG Packet captured src=192.168.1.100 dst=192.168.1.1 protocol=ARP
2024-01-15T12:45:30.125678Z INF Host discovered mac=00:11:22:33:44:55 ip=192.168.1.100 vendor=Cisco
2024-01-15T12:45:30.126789Z WRN Anomaly detected type=arp_storm severity=high
2024-01-15T12:45:30.127890Z ERR Failed to parse packet error="invalid protocol"
```

### Log Fields

| Field | Description | Example |
|-------|-------------|---------|
| **Timestamp** | ISO 8601 timestamp with microseconds | `2024-01-15T12:45:30.123456Z` |
| **Level** | Log level abbreviation | `INF`, `DBG`, `WRN`, `ERR` |
| **Message** | Human-readable log message | `Host discovered` |
| **Context** | Key-value pairs with additional data | `mac=00:11:22:33:44:55 ip=192.168.1.100` |

## Configuration

### YAML Configuration

```yaml
logging:
  verbose: false    # Enable verbose logging
  quiet: false      # Enable quiet logging
  paranoid: false   # Suppress all stdout output
```

### CLI Override

Command-line flags override configuration file settings:

```bash
# Override config file logging settings
zandoli --verbose --config config.yaml

# Quiet mode override
zandoli --quiet --config config.yaml

# Paranoid mode override
zandoli --paranoid --config config.yaml
```

## Log File Management

### File Locations

#### Global Log File
- **Path**: `output/log.txt`
- **Purpose**: Application-wide logging
- **Mode**: Append (preserves previous logs)
- **Content**: All log levels from all scan sessions

#### Scan-Specific Log Files
- **Path**: `output/scan_TIMESTAMP/log.txt`
- **Purpose**: Individual scan session logging
- **Mode**: Create (new file per scan)
- **Content**: Detailed logs for specific scan session

### File Permissions
- **Default**: `0644` (readable by all users)
- **Directory**: `0755` (accessible by all users)
- **Log rotation**: Not implemented (manual rotation required)

### Log Rotation Policy

**Note**: Zandoli does not implement automatic log rotation. Manual log management is required:

```bash
# Manual log rotation example
mv output/log.txt output/log.txt.old
touch output/log.txt

# Archive old logs
tar -czf logs-archive.tar.gz output/scan_*
```

## Logging Examples

### Verbose Logging Output

```bash
$ zandoli --verbose --pcap traffic.pcap
2024-01-15T12:45:30.123456Z INF Zandoli V2 – Stealth Network Scanner
2024-01-15T12:45:30.124567Z INF Loading configuration file=config.yaml
2024-01-15T12:45:30.125678Z INF Opening PCAP file=traffic.pcap
2024-01-15T12:45:30.126789Z DBG PCAP file opened packets=1250 size=2.5MB
2024-01-15T12:45:30.127890Z DBG Starting packet processing workers=4
2024-01-15T12:45:30.128901Z DBG Packet 1/1250 src=192.168.1.100 dst=192.168.1.1 protocol=ARP
2024-01-15T12:45:30.129912Z INF ARP packet parsed src_mac=00:11:22:33:44:55 src_ip=192.168.1.100
2024-01-15T12:45:30.130923Z INF Host discovered mac=00:11:22:33:44:55 ip=192.168.1.100
2024-01-15T12:45:30.131934Z DBG OUI lookup mac=00:11:22:33 vendor=Cisco Systems
2024-01-15T12:45:30.132945Z INF Role inference completed role=reseau confidence=90 signals=OUI_INFRA
```

### Quiet Logging Output

```bash
$ zandoli --quiet --passive --passive-duration 60
2024-01-15T12:45:30.123456Z INF Scan started duration=60s
2024-01-15T12:46:30.123456Z INF Scan completed hosts=25 subnets=3
```

### Paranoid Logging Output

```bash
$ zandoli --paranoid --passive --passive-duration 60
# No console output - all logs go to files only
```

## Log Context Fields

### Common Context Fields

| Field | Description | Example |
|-------|-------------|---------|
| `interface` | Network interface name | `interface=eth0` |
| `mode` | Scan mode | `mode=passive` |
| `duration` | Scan duration | `duration=60s` |
| `packets` | Packet count | `packets=1250` |
| `hosts` | Host count | `hosts=25` |
| `subnets` | Subnet count | `subnets=3` |

### Host-Related Fields

| Field | Description | Example |
|-------|-------------|---------|
| `mac` | MAC address | `mac=00:11:22:33:44:55` |
| `ip` | IP address | `ip=192.168.1.100` |
| `vendor` | Device vendor | `vendor=Cisco Systems` |
| `role` | Inferred role | `role=reseau` |
| `confidence` | Role confidence | `confidence=90` |
| `signals` | Role signals | `signals=OUI_INFRA` |

### Protocol-Related Fields

| Field | Description | Example |
|-------|-------------|---------|
| `protocol` | Protocol name | `protocol=ARP` |
| `src` | Source address | `src=192.168.1.100` |
| `dst` | Destination address | `dst=192.168.1.1` |
| `port` | Port number | `port=80` |
| `vlan` | VLAN ID | `vlan=10` |

### Error-Related Fields

| Field | Description | Example |
|-------|-------------|---------|
| `error` | Error message | `error="invalid protocol"` |
| `file` | File path | `file=traffic.pcap` |
| `line` | Source line number | `line=123` |
| `function` | Function name | `function=parsePacket` |

## Performance Logging

### Metrics Logging

When enabled, Zandoli logs performance metrics:

```bash
# Enable metrics logging (if implemented)
zandoli --enable-metrics --pcap traffic.pcap
```

Example metrics logs:
```
2024-01-15T12:45:30.123456Z INF Performance metrics packets_per_second=1250 memory_usage=45MB
2024-01-15T12:45:30.124567Z INF Processing statistics workers=4 queue_size=0 processed=1250
```

### Memory Usage Logging

Memory usage is logged periodically during long scans:

```
2024-01-15T12:45:30.123456Z INF Memory usage allocated=45MB heap=40MB goroutines=8
```

## Log Analysis

### Common Log Patterns

#### Successful Scan
```
INF Scan started
INF Host discovered (multiple entries)
INF Role inference completed (multiple entries)
INF Scan completed hosts=X subnets=Y
```

#### Error Conditions
```
ERR Failed to open PCAP file=traffic.pcap error="file not found"
ERR Permission denied interface=eth0
ERR Invalid configuration file=config.yaml error="yaml syntax error"
```

#### Anomaly Detection
```
WRN Anomaly detected type=arp_storm severity=high
WRN Anomaly detected type=mac_multiple_ip severity=medium
WRN Anomaly detected type=duplicate_hostname severity=low
```

### Log Filtering and Analysis

#### Using grep for Log Analysis
```bash
# Find all host discoveries
grep "Host discovered" output/log.txt

# Find all errors
grep "ERR" output/log.txt

# Find anomalies
grep "Anomaly detected" output/log.txt

# Find specific MAC address
grep "mac=00:11:22:33:44:55" output/log.txt
```

#### Using jq for JSON Log Analysis
```bash
# Parse JSON logs (if JSON format is enabled)
cat output/log.txt | jq '.level == "ERR"'

# Filter by specific fields
cat output/log.txt | jq 'select(.mac == "00:11:22:33:44:55")'
```

## Debugging with Logs

### Common Debugging Scenarios

#### No Hosts Discovered
```bash
# Check for packet capture issues
grep -E "(packet|capture)" output/log.txt

# Check for parsing errors
grep "ERR" output/log.txt

# Check for interface issues
grep "interface" output/log.txt
```

#### Role Inference Issues
```bash
# Check role inference logs
grep "Role inference" output/log.txt

# Check for conflicting signals
grep "RoleConflict" output/log.txt

# Check OUI lookup results
grep "OUI lookup" output/log.txt
```

#### Performance Issues
```bash
# Check memory usage
grep "Memory usage" output/log.txt

# Check processing rates
grep "packets_per_second" output/log.txt

# Check worker performance
grep "workers" output/log.txt
```

## Log Security Considerations

### Sensitive Information

Zandoli logs may contain sensitive network information:

- **IP addresses** of discovered hosts
- **MAC addresses** of network devices
- **Hostnames** and device identifiers
- **Network topology** information

### Log Protection

#### File Permissions
```bash
# Restrict log file access
chmod 600 output/log.txt
chmod 700 output/

# Set proper ownership
chown zandoli:zandoli output/log.txt
```

#### Log Sanitization

For production environments, consider log sanitization:

```bash
# Remove sensitive information from logs
sed -i 's/192\.168\.[0-9]*\.[0-9]*/XXX.XXX.XXX.XXX/g' output/log.txt
sed -i 's/mac=[0-9a-f:]*/mac=XX:XX:XX:XX:XX:XX/g' output/log.txt
```

## Integration with External Logging

### Syslog Integration

For enterprise environments, consider forwarding logs to syslog:

```bash
# Forward logs to syslog (example)
tail -f output/log.txt | logger -t zandoli -p local0.info
```

### Log Aggregation

For centralized logging, integrate with:

- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk** for enterprise log analysis
- **Graylog** for open-source log management
- **Fluentd** for log forwarding

## See Also

- [CLI Reference](CLI.md)
- [Configuration](ARCHITECTURE.md#configuration)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Security Considerations](SECURITY.md)
