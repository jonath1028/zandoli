# Glossary

This document defines networking terms, protocols, and concepts used throughout Zandoli.

## Networking Terms

### Address Resolution Protocol (ARP)
A protocol used to map IP addresses to MAC addresses on a local network. ARP requests and replies are used to discover the MAC address associated with an IP address.

### Border Gateway Protocol (BGP)
An exterior gateway protocol used to exchange routing information between autonomous systems on the Internet.

### Cisco Discovery Protocol (CDP)
A proprietary Layer 2 protocol developed by Cisco Systems for network device discovery and information exchange. CDP packets contain information about device capabilities, platform, and management addresses.

### Dynamic Host Configuration Protocol (DHCP)
A network protocol that automatically assigns IP addresses and other network configuration parameters to devices on a network.

### Domain Name System (DNS)
A hierarchical naming system that translates domain names to IP addresses and vice versa.

### Ethernet
A family of wired networking technologies commonly used in local area networks (LANs).

### Internet Control Message Protocol (ICMP)
A supporting protocol used by network devices to send error messages and operational information.

### Internet Protocol (IP)
The principal communications protocol for relaying datagrams across network boundaries.

### Link Layer Discovery Protocol (LLDP)
An IEEE 802.1AB standard protocol for network device discovery and information exchange. LLDP is vendor-neutral and provides similar functionality to CDP.

### MAC Address
A unique identifier assigned to network interfaces for communications at the data link layer of a network segment.

### Network Address Translation (NAT)
A method of remapping IP address space by modifying network address information in IP packet headers.

### Open Systems Interconnection (OSI) Model
A conceptual model that characterizes and standardizes the communication functions of a telecommunication or computing system.

### Organizationally Unique Identifier (OUI)
A 24-bit number that uniquely identifies a vendor, manufacturer, or organization for the purpose of creating globally unique MAC addresses.

### Port
A communication endpoint in computer networking. Ports are identified by numbers and are used to distinguish between different services or applications.

### Protocol
A set of rules and standards that define how devices communicate over a network.

### Spanning Tree Protocol (STP)
A network protocol that prevents loops in switched networks by creating a spanning tree topology.

### Transmission Control Protocol (TCP)
A connection-oriented protocol that provides reliable, ordered, and error-checked delivery of data between applications.

### User Datagram Protocol (UDP)
A connectionless protocol that provides a simple, unreliable datagram service.

### Virtual Local Area Network (VLAN)
A logical grouping of devices on a network that allows for network segmentation and improved security.

### 802.1X
An IEEE standard for port-based network access control that provides authentication for devices attempting to connect to a network.

## Zandoli-Specific Terms

### Active Scanning
A method of network discovery that involves sending probe packets to discover hosts and services. Zandoli uses ARP and SYN scanning for active discovery.

### Aggregator
The core component that collects and correlates information from various protocol parsers to build a unified view of network hosts.

### Anomaly Detection
The process of identifying unusual patterns or behaviors in network traffic that may indicate security issues or network problems.

### Client
A device or application that initiates requests to servers. In Zandoli's role inference, clients are identified by their behavior patterns (e.g., initiating connections, making requests).

### Combined Mode
A scanning mode that runs both passive sniffing and active scanning to provide comprehensive network discovery.

### Data Fusion
The process of merging information from multiple sources (passive and active scanning) to create a unified, accurate view of network hosts.

### Exporter
A component that generates reports in various formats (HTML, CSV, JSON, etc.) from the discovered network data.

### Host
A network device discovered by Zandoli, represented by a MAC address and associated IP addresses, protocols, and other characteristics.

### Layer 2 (L2)
The data link layer of the OSI model, which includes protocols like CDP, LLDP, STP, and 802.1X that operate at this layer.

### Layer 3 (L3)
The network layer of the OSI model, which includes protocols like IP, ICMP, and routing protocols.

### Orchestrator
The central component that coordinates the execution of the entire scanning pipeline, managing the flow of data between different components.

### Passive Scanning
A method of network discovery that involves analyzing existing network traffic without sending additional packets.

### PCAP
A file format used to store captured network packets. PCAP files can be analyzed offline to discover network hosts and protocols.

### Protocol Parser
A component that extracts information from specific network protocols (e.g., CDP, LLDP, DHCP, ARP).

### Role Inference
The process of determining a device's role (client, server, or network infrastructure) based on observed behavior and protocol information.

### Server
A device or application that responds to requests from clients. In Zandoli's role inference, servers are identified by their behavior patterns (e.g., responding to requests, providing services).

### Sniffer
A component that captures network packets from live interfaces or reads them from PCAP files.

### Subnet
A logical subdivision of an IP network that allows for efficient address allocation and network management.

### Topology
The physical or logical arrangement of network devices and their interconnections.

## Protocol-Specific Terms

### CDP Terms

#### Device ID
A unique identifier for a CDP-capable device, typically the device's hostname or fully qualified domain name.

#### Platform
The hardware platform or model of a CDP-capable device.

#### Capabilities
A bitmask that indicates the device's capabilities (e.g., router, switch, host, phone).

#### Native VLAN
The default VLAN for untagged traffic on a switch port.

#### Management Addresses
IP addresses that can be used to manage the device.

### LLDP Terms

#### Chassis ID
A unique identifier for the LLDP-capable device, typically a MAC address, IP address, or hostname.

#### Port ID
An identifier for the port through which the LLDP packet was sent.

#### System Name
The device's hostname or system name.

#### System Description
A description of the device's hardware and software.

#### System Capabilities
A bitmask that indicates the device's capabilities (e.g., bridge, router, station).

### STP Terms

#### Bridge ID
A unique identifier for a bridge, consisting of a priority value and the bridge's MAC address.

#### Root Bridge
The bridge with the lowest bridge ID that serves as the root of the spanning tree.

#### Root Path Cost
The cost to reach the root bridge from a given bridge.

#### Port ID
An identifier for a bridge port, consisting of a priority value and a port number.

#### Hello Time
The interval between transmission of configuration BPDUs.

#### Max Age
The maximum age of BPDU information before it is discarded.

#### Forward Delay
The time a port waits before transitioning to the forwarding state.

### DHCP Terms

#### DHCP Server
A device that provides IP addresses and configuration parameters to DHCP clients.

#### DHCP Client
A device that requests IP addresses and configuration parameters from a DHCP server.

#### Lease Time
The duration for which a DHCP client can use an assigned IP address.

#### DHCP Options
Additional configuration parameters sent by DHCP servers to clients.

### ARP Terms

#### ARP Request
A packet sent by a device to discover the MAC address associated with an IP address.

#### ARP Reply
A packet sent in response to an ARP request, containing the requested MAC address.

#### ARP Table
A table maintained by network devices that maps IP addresses to MAC addresses.

## Network Topology Terms

### Access Point (AP)
A device that allows wireless devices to connect to a wired network.

### Bridge
A device that connects multiple network segments and forwards traffic between them.

### Gateway
A device that connects different networks and routes traffic between them.

### Hub
A basic networking device that broadcasts traffic to all connected devices.

### Router
A device that forwards data packets between different networks.

### Switch
A device that connects multiple devices on a network and forwards traffic only to the intended recipient.

### Repeater
A device that amplifies or regenerates network signals to extend the range of a network.

## Security Terms

### Anomaly
An unusual pattern or behavior in network traffic that may indicate a security issue or network problem.

### ARP Storm
A network condition where a large number of ARP requests are sent, potentially causing network congestion.

### MAC Flooding
An attack where an attacker sends a large number of frames with different MAC addresses to overwhelm a switch's MAC table.

### Port Scanning
The process of scanning a network to identify open ports and services on target hosts.

### SYN Flood
A type of denial-of-service attack where an attacker sends a large number of SYN requests to overwhelm a target server.

### VLAN Hopping
An attack where an attacker attempts to access traffic from other VLANs by exploiting VLAN configuration vulnerabilities.

## Data Analysis Terms

### Confidence Score
A numerical value (0-100) that indicates the reliability of a role inference or other analysis result.

### Correlation
The process of associating information from different sources to create a unified view.

### Deduplication
The process of removing duplicate entries or information from a dataset.

### Inference
The process of drawing conclusions from observed data and patterns.

### Signal
A piece of information or behavior that indicates a particular characteristic or role.

### Strength
A measure of the reliability or importance of a particular piece of information or correlation.

## See Also

- [Layer 2 Protocols](L2_PROTOCOLS.md)
- [Pipeline Processing](PIPELINE.md)
- [Data Model](DATA_MODEL.md)
- [Architecture Overview](ARCHITECTURE.md)
