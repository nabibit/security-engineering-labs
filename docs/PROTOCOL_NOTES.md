# Protocol Notes – Ethernet & ARP

## Ethernet Frame Structure (RFC 894)

| Offset | Field | Size (bytes) | Description |
|--------|-------|--------------|-------------|
| 0-5    | Destination MAC | 6 | MAC address of the receiver |
| 6-11   | Source MAC | 6 | MAC address of the sender |
| 12-13  | EtherType | 2 | Protocol type (e.g., 0x0800 = IPv4, 0x0806 = ARP) |
| 14-... | Payload | 46-1500 | Data (IP packet, ARP packet, etc.) |
| End    | FCS (Frame Check Sequence) | 4 | CRC checksum |

### Common EtherType Values
- `0x0800` – IPv4
- `0x0806` – ARP
- `0x86DD` – IPv6

---

## ARP Packet Structure (RFC 826)

| Offset | Field | Size (bytes) | Description |
|--------|-------|--------------|-------------|
| 0-1    | Hardware Type | 2 | 1 = Ethernet |
| 2-3    | Protocol Type | 2 | 0x0800 = IPv4 |
| 4      | Hardware Address Length | 1 | 6 (MAC) |
| 5      | Protocol Address Length | 1 | 4 (IPv4) |
| 6-7    | Operation | 2 | 1 = Request, 2 = Reply |
| 8-13   | Sender MAC | 6 | |
| 14-17  | Sender IP | 4 | |
| 18-23  | Target MAC | 6 | |
| 24-27  | Target IP | 4 | |

### ARP Opcodes
- `1` – ARP Request (Who has this IP?)
- `2` – ARP Reply (I have this IP!)

---

## Why This Matters
Understanding packet headers at the byte level is essential for:
- **Network troubleshooting** – identifying malformed packets.
- **Security analysis** – detecting ARP spoofing, packet injection.
- **Protocol reverse engineering** – understanding custom protocols.

## IPv4 Header Structure (RFC 791)

| Offset | Field | Size (bits) | Size (bytes) | Description |
|--------|-------|-------------|--------------|-------------|
| 0      | Version | 4 | - | IPv4 = 4 |
| 0      | IHL (Internet Header Length) | 4 | - | Header length in 32-bit words (IHL × 4 = bytes) |
| 1      | TOS (Type of Service) | 8 | 1 | DSCP + ECN |
| 2-3    | Total Length | 16 | 2 | Total packet length (header + payload) |
| 4-5    | Identification | 16 | 2 | Unique packet identifier |
| 6      | Flags | 3 | - | DF (Don't Fragment), MF (More Fragments) |
| 6-7    | Fragment Offset | 13 | - | Fragment position (in 8-byte units) |
| 8      | TTL (Time to Live) | 8 | 1 | Max hops before packet discarded |
| 9      | Protocol | 8 | 1 | Transport protocol (6=TCP, 17=UDP, 1=ICMP) |
| 10-11  | Header Checksum | 16 | 2 | Error detection for header only |
| 12-15  | Source IP | 32 | 4 | IPv4 address of sender |
| 16-19  | Destination IP | 32 | 4 | IPv4 address of receiver |

### Key Formulas
- **IHL (Internet Header Length):** `IHL × 4 = Header Length (bytes)`.
  - Example: IHL = 5 → Header length = 20 bytes (standard IPv4 header).
- **Total Length:** `Header Length + Payload Length`.
- **Fragment Offset:** Multiplied by 8 to get byte offset.

### Common Protocol Numbers
- `1` – ICMP
- `6` – TCP
- `17` – UDP
- `89` – OSPF

### Why This Matters
Understanding the IPv4 header is essential for:
- **Packet filtering:** Firewalls inspect protocol/port fields.
- **Troubleshooting:** TTL tells you how many hops a packet took.
- **Security:** Detecting malformed packets, fragmentation attacks.

## UDP Header (RFC 768)

| Offset | Field | Size (bytes) | Description |
|--------|-------|--------------|-------------|
| 0-1    | Source Port | 2 | Sending port (0 = none) |
| 2-3    | Destination Port | 2 | Receiving port |
| 4-5    | Length | 2 | UDP header + payload (minimum 8) |
| 6-7    | Checksum | 2 | Optional (0 = none) |

## ICMP Header (RFC 792)

| Offset | Field | Size (bytes) | Description |
|--------|-------|--------------|-------------|
| 0      | Type | 1 | 8 = Echo Request, 0 = Echo Reply |
| 1      | Code | 1 | Sub-type (usually 0) |
| 2-3    | Checksum | 2 | Error detection |
| 4-...  | Payload | variable | Varies by type (e.g., identifier, sequence) |

### Common ICMP Types
- `0` – Echo Reply (ping response)
- `3` – Destination Unreachable
- `8` – Echo Request (ping)
- `11` – Time Exceeded (traceroute)

## TCP Header (RFC 793)

| Offset | Field | Size (bytes) | Description |
|--------|-------|--------------|-------------|
| 0-1    | Source Port | 2 | Sender's port |
| 2-3    | Destination Port | 2 | Receiver's port |
| 4-7    | Sequence Number | 4 | Position of first data byte |
| 8-11   | Acknowledgment Number | 4 | Next expected byte |
| 12     | Data Offset (4 bits) | - | Header length in 32-bit words (×4 = bytes) |
| 12     | Reserved (3 bits) | - | Must be 0 |
| 12-13  | Flags (9 bits) | - | NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN |
| 14-15  | Window Size | 2 | Receive window size |
| 16-17  | Checksum | 2 | Error detection |
| 18-19  | Urgent Pointer | 2 | Offset for urgent data |
| 20-... | Options | variable | Optional (MSS, window scaling, SACK) |

### TCP Flags (bit values)
- `FIN` – 0x01 – No more data from sender
- `SYN` – 0x02 – Synchronize sequence numbers
- `RST` – 0x04 – Reset connection
- `PSH` – 0x08 – Push buffered data
- `ACK` – 0x10 – Acknowledgment field is valid
- `URG` – 0x20 – Urgent pointer field is valid
- `ECE` – 0x40 – ECN Echo
- `CWR` – 0x80 – Congestion Window Reduced

### Common TCP Ports
- `20/21` – FTP
- `22` – SSH
- `23` – Telnet
- `25` – SMTP
- `80` – HTTP
- `110` – POP3
- `143` – IMAP
- `443` – HTTPS
- `3306` – MySQL
- `3389` – RDP