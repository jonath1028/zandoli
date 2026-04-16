# Layer 2 Protocols

This document details the Layer 2 protocols that Zandoli analyzes and the information extracted from each protocol.

## Overview

Zandoli analyzes several Layer 2 protocols to identify network infrastructure devices and gather detailed device information. These protocols provide the highest confidence level for role inference, taking precedence over all other detection methods.

## Supported Protocols

### CDP (Cisco Discovery Protocol)

CDP is a Cisco proprietary protocol that runs on Cisco devices to share information about connected devices.

#### Information Extracted

| TLV | Field | Description |
|-----|-------|-------------|
| 0x01 | Device ID | Device name or hostname |
| 0x03 | Port ID | Interface identifier |
| 0x06 | Platform | Hardware platform/model |
| 0x05 | Software Version | IOS/software version |
| 0x04 | Capabilities | Device capabilities bitmask |
| 0x0a | Native VLAN | Native VLAN ID |
| 0x02 | Management Addresses | IP addresses for management |

#### Capabilities Decoding

CDP capabilities are represented as a bitmask with the following values:

| Bit | Value | Capability |
|-----|-------|------------|
| 0 | 0x01 | Router |
| 1 | 0x02 | Transparent Bridge |
| 2 | 0x04 | Source Route Bridge |
| 3 | 0x08 | Switch/Bridge |
| 4 | 0x10 | Host |
| 5 | 0x20 | IGMP |
| 6 | 0x40 | Repeater |
| 7 | 0x80 | Phone/AP |

#### Example CDP Data

```json
{
  "device_id": "sw-core-01.example.com",
  "platform": "WS-C2960-24TC-L",
  "version": "C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE7",
  "capabilities": 41,
  "decoded_caps": ["Router", "Switch/Bridge"],
  "native_vlan": 1,
  "addresses": ["192.168.1.1", "10.0.0.1"]
}
```

### LLDP (Link Layer Discovery Protocol)

LLDP is an IEEE 802.1AB standard protocol for network device discovery and information exchange.

#### Information Extracted

| TLV | Field | Description |
|-----|-------|-------------|
| 1 | Chassis ID | Device identifier (MAC, IP, or hostname) |
| 2 | Port ID | Interface identifier |
| 5 | System Name | Device name |
| 6 | System Description | Hardware and software description |
| 7 | System Capabilities | Device capabilities |
| 8 | Management Addresses | Management IP addresses |

#### Capabilities Decoding

LLDP capabilities are represented as a bitmask:

| Bit | Capability | Description |
|-----|------------|-------------|
| 0 | Other | Other capabilities |
| 1 | Repeater | Repeater capability |
| 2 | Bridge | Bridge capability |
| 3 | WLAN Access Point | WLAN AP capability |
| 4 | Router | Router capability |
| 5 | Telephone | IP telephone capability |
| 6 | DOCSIS Cable Device | Cable device capability |
| 7 | Station Only | End station capability |

#### Example LLDP Data

```json
{
  "chassis_id": "00:11:22:33:44:55",
  "port_id": "GigabitEthernet0/1",
  "sys_name": "router-01",
  "sys_descr": "Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4",
  "capabilities": ["Router", "Bridge"],
  "mgmt_addrs": ["192.168.1.1"]
}
```

### STP (Spanning Tree Protocol)

STP is used to prevent loops in switched networks by creating a spanning tree topology.

#### Information Extracted

| Field | Description |
|-------|-------------|
| Root Bridge ID | MAC address of the root bridge |
| Bridge ID | MAC address of the sending bridge |
| Port ID | Port identifier |
| Root Path Cost | Cost to reach the root bridge |
| Hello Time | Hello timer value |
| Max Age | Maximum age for BPDUs |
| Forward Delay | Forward delay timer |
| Message Age | Age of the BPDU message |

#### Example STP Data

```json
{
  "root_bridge_id": "0000.1111.2222.3333",
  "bridge_id": "0000.4444.5555.6666",
  "port_id": 128,
  "root_path_cost": 4,
  "hello_time": 2,
  "max_age": 20,
  "forward_delay": 15,
  "message_age": 1,
  "is_root": false
}
```

### 802.1X (EAPOL)

802.1X is an IEEE standard for port-based network access control.

#### Information Extracted

| Field | Description |
|-------|-------------|
| EAPOL Presence | Detection of EAPOL frames |
| Authentication State | Authentication activity observed |

#### Example 802.1X Data

```json
{
  "eapol": true
}
```

## VLAN Information

### VLAN Detection

VLANs are detected from:

1. **802.1Q Tags**: VLAN IDs in packet headers
2. **CDP Native VLAN**: Native VLAN information from CDP
3. **DHCP VLAN Options**: VLAN information in DHCP messages
4. **Port-based VLANs**: Inferred from switch behavior

### VLAN Statistics

For each host, Zandoli tracks:

- **VLAN List**: All observed VLAN IDs
- **VLAN Statistics**: Frame count per VLAN
- **Primary VLAN**: Most frequently observed VLAN

#### Example VLAN Data

```json
{
  "vlans": [1, 10, 20],
  "vlanStats": {
    "1": 150,
    "10": 75,
    "20": 25
  },
  "primaryVlan": 1
}
```

## L2 Details Display Rules

### Strict Layer 2 Only

The "L2 Details" section in reports contains **only** information from Layer 2 protocols:

- ✅ **CDP**: Device ID, Platform, Version, Capabilities, Native VLAN
- ✅ **LLDP**: System Name, System Description, Chassis ID, Capabilities
- ✅ **STP**: Root Bridge ID, Bridge ID, Root Path Cost
- ✅ **802.1X**: EAPOL detection status
- ✅ **VLANs**: List of observed VLAN IDs

### Excluded Information

The following information is **not** included in L2 Details:

- ❌ **OUI/Vendor**: MAC address vendor lookup (appears in "Vendor" column)
- ❌ **Port IDs**: Physical port identifiers (not Layer 2 protocol data)
- ❌ **IP Addresses**: Management IPs (appear in IP columns)
- ❌ **Application Protocols**: HTTP, DNS, etc. (appear in "Protocols" column)

## MAC↔IP Correlation

### Correlation Logic

Layer 2 protocol information is correlated with IP addresses through:

1. **Direct Association**: L2 protocol packets contain both MAC and IP information
2. **Management Addresses**: CDP/LLDP management address TLVs
3. **Packet Source**: Source MAC/IP from L2 protocol packets
4. **VLAN Context**: VLAN-aware correlation for multi-VLAN scenarios

### Multi-IP Scenarios

When a device has multiple IP addresses:

- **Primary IP**: Selected based on priority rules (RFC1918 private > public)
- **All IPs**: All observed IP addresses are stored and displayed
- **VLAN Separation**: IPs may be associated with different VLANs

## Role Inference Priority

### Layer 2 Priority Rules

1. **Absolute Priority**: Any L2 protocol presence (CDP, LLDP, STP, 802.1X) → Role = "reseau"
2. **Confidence Level**: 100% confidence for L2-detected devices
3. **Override**: L2 protocols override all other role inference methods
4. **Short-circuit**: No further analysis needed when L2 protocols are present

### Fallback Hierarchy

```
L2 Protocols (CDP/LLDP/STP/802.1X) → Role = "reseau" (100%)
    ↓ (if no L2)
OUI Network Vendor → Role = "reseau" (90%)
    ↓ (if no L2, no network OUI)
Behavioral Analysis → Role = "client"/"server" (variable)
```

## Protocol-Specific Examples

### Network Switch (CDP)

```json
{
  "macStr": "00:11:22:33:44:55",
  "role": "reseau",
  "roleConfidence": 100,
  "roleSignals": ["L2_PRESENT"],
  "cdp": {
    "device_id": "sw-access-01",
    "platform": "WS-C2960-24TC-L",
    "version": "C2960 Software, Version 12.2(55)SE7",
    "capabilities": 41,
    "native_vlan": 1
  },
  "l2": {
    "vlans": [1, 10, 20],
    "cdp": true
  }
}
```

### Network Router (LLDP)

```json
{
  "macStr": "00:aa:bb:cc:dd:ee",
  "role": "reseau",
  "roleConfidence": 100,
  "roleSignals": ["L2_PRESENT"],
  "lldp": {
    "chassis_id": "00:aa:bb:cc:dd:ee",
    "sys_name": "router-core-01",
    "sys_descr": "Cisco IOS Software, C2900 Software, Version 15.1(4)M4",
    "capabilities": ["Router", "Bridge"]
  },
  "l2": {
    "vlans": [1, 100],
    "lldp": true
  }
}
```

### STP Root Bridge

```json
{
  "macStr": "00:ff:ff:ff:ff:ff",
  "role": "reseau",
  "roleConfidence": 100,
  "roleSignals": ["L2_PRESENT"],
  "stp": {
    "root_bridge_id": "0000.ffff.ffff.ffff",
    "bridge_id": "0000.ffff.ffff.ffff",
    "root_path_cost": 0,
    "is_root": true
  },
  "l2": {
    "vlans": [1],
    "stp": true
  }
}
```

## Troubleshooting L2 Details

### Common Issues

1. **No L2 Details**: Device not sending CDP/LLDP/STP frames
   - Check if protocols are enabled on the device
   - Verify network connectivity and VLAN configuration

2. **Incomplete Information**: Partial L2 protocol data
   - Ensure sufficient capture time for complete protocol exchange
   - Check for packet loss or filtering

3. **Missing VLAN Information**: No VLAN data in L2 details
   - Verify 802.1Q tagging is enabled
   - Check VLAN configuration on switches

### Validation Checklist

- [ ] CDP packets contain Device ID and Platform information
- [ ] LLDP packets contain System Name and Description
- [ ] STP BPDUs show valid Bridge IDs and path costs
- [ ] 802.1Q tags are present in VLAN traffic
- [ ] Management addresses are correctly parsed from CDP/LLDP

## See Also

- [Data Model](DATA_MODEL.md)
- [Pipeline Processing](PIPELINE.md)
- [Role Inference](PIPELINE.md#role-inference-algorithm)
- [Troubleshooting](TROUBLESHOOTING.md)
