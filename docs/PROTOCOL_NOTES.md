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