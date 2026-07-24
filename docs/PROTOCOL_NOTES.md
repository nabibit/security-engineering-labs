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