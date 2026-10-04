# 🔬 security-engineering-labs

![Under Construction](https://img.shields.io/badge/Status-Under%20Construction-yellow)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Manipulation-brightgreen)
![License](https://img.shields.io/badge/License-MIT-orange)

> ⚠️ **This repository is under active development.** More labs, tools, and documentation are being added regularly.

A hands-on practice repository for network security engineering, focusing on packet analysis, protocol manipulation, and network tool development. This lab accompanies my self-study in preparation for security and operations roles.

## Table of Contents
- [Purpose](#purpose)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Tools & Environments](#tools--environments)
- [Scripts](#scripts)
- [Testing the Tools](#testing-the-tools)
- [Documentation](#documentation)
- [Acknowledgements](#acknowledgements)

## Purpose
- Explore network protocols at the packet level using Scapy.
- Build tools for packet sniffing, analysis, and manipulation.
- Document daily progress, commands, and observations in the [learning log](docs/LEARNING_LOG.md).

## Repository Structure
- `src/` – Python scripts and network utilities.
- `docs/` – Learning log and screenshots from lab exercises.
- `requirements.txt` – Python dependencies.

## Getting Started

1. Clone the repo:

```bash
git clone https://github.com/nabibit/security-engineering-labs.git
cd security-engineering-labs
```

2. (Optional) Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Tools & Environments

- **Linux VM / WSL**: Ubuntu environment for running Scapy and packet analysis.
- **Scapy**: Packet manipulation library for Python.
- **Npcap/WinPcap**: Required on Windows for packet capture.

---

## Scripts

Located in `src/`:

| Script | Purpose | Example Usage |
|--------|---------|---------------|
| `sniffer/live_sniffer.py` | Captures live packets and displays raw bytes in hex and ASCII format. | `sudo python3 src/sniffer/live_sniffer.py` |
| `sniffer/protocol_sniffer.py` | Captures raw packets and manually dissects Ethernet and ARP headers using byte offsets and `struct` unpacking. | `sudo python3 src/sniffer/protocol_sniffer.py` |
| `sniffer/custom_packet.py` | Crafts custom ICMP Echo Request packets with manual checksum calculation. | `sudo python3 src/sniffer/custom_packet.py 8.8.8.8 3` |
| `protocols/ipv4.py` | Manually dissects RFC 791 IPv4 headers (version, IHL, TTL, protocol, source/dest IP). | *Imported and run via `protocol_sniffer.py`* |
| `protocols/udp.py` | Manually dissects RFC 768 UDP headers (source/dest ports, length, checksum) and maps services. | *Imported and run via `protocol_sniffer.py`* |
| `protocols/icmp.py` | Manually dissects RFC 792 ICMP headers (type, code, checksum) and identifies message types. | *Imported and run via `protocol_sniffer.py`* |
| `protocols/tcp.py` | Manually dissects RFC 793 TCP headers (ports, sequence/ack numbers, flags, window, checksum) and maps common services. | *Imported and run via `protocol_sniffer.py` (integration pending)* |

**Dependencies:**
- `scapy` – Install via `pip install scapy`.
- `libpcap` / `Npcap` – Required for packet capture (install via system package manager).
- On Linux: `sudo apt install libpcap-dev -y`

**Usage examples:**

```bash
# Run the live sniffer (requires root privileges)
sudo python3 src/sniffer/live_sniffer.py

# Run the manual Ethernet & ARP dissector (requires root privileges)
sudo python3 src/sniffer/protocol_sniffer.py
```

---

## Testing the Tools

Each module includes a self-test or can be run directly to verify functionality. Run these commands from the project root (`security-engineering-labs/`).

### Live Sniffer

```bash
# Run the sniffer (root privileges required)
sudo python3 src/sniffer/live_sniffer.py
```

Generate traffic to see packets:

```bash
ping -c 5 google.com
```

### Ethernet & ARP Dissector

```bash
# Run the dissector (root privileges required)
sudo python3 src/sniffer/protocol_sniffer.py
```
Generate ARP traffic to verify manual payload parsing:

```bash
sudo ip neigh flush all
ping -c 3 10.0.2.2
```

### Protocol Dissector (Ethernet, ARP & IPv4)

```bash
# Run the dissector (root privileges required)
sudo python3 src/sniffer/protocol_sniffer.py
```

Generate traffic to verify manual payload parsing:

```bash
# For ARP testing:
sudo ip neigh flush all
ping -c 3 10.0.2.2

# For IPv4 testing:
ping -c 3 google.com
```

### UDP & ICMP Dissectors

```bash
# Run the dissector (root privileges required)
sudo python3 src/sniffer/protocol_sniffer.py
```
Generate traffic to verify manual Layer 4 and control protocol parsing:

```bash 
# For ICMP (Echo Request / Reply) testing:
ping -c 3 8.8.8.8

# For UDP (DNS query on port 53 or NTP on port 123) testing:
dig @8.8.8.8 google.com
```

### TCP Dissector (Module-Level Test)

TCP dissection is currently available as a standalone module. Direct testing verifies the parser without requiring live integration:

```bash
# Run from the repository root
python3 -c "
from src.protocols.tcp import dissect_tcp

# Simulated TCP SYN packet header (20 bytes)
# Src Port 54321, Dst Port 80, Seq 0, Ack 0, Data Offset 5, Flags SYN, Window 65535
header = bytes.fromhex('d431005000000000000000005002ffff00000000')
result = dissect_tcp(header)
print('Source Port:', result['src_port'])
print('Dest Port:  ', result['dest_port'], '(HTTP)')
print('Flags:      ', result['flag_names'])
print('Header Len: ', result['header_len'], 'bytes')
"
```

### Custom Packet Crafting
Build and send custom ICMP Echo Request packets with manual checksum calculation.

```bash
# Send 3 custom pings to 8.8.8.8
sudo python3 src/sniffer/custom_packet.py 8.8.8.8 3
```

---

## Documentation

See [docs/LEARNING_LOG.md](docs/LEARNING_LOG.md) for the detailed engineering journal.

The log tracks daily progress, concepts, artifacts, and reflections – from packet sniffing to protocol manipulation.

---

## Acknowledgements

Built while studying *Computer Networking: A Top-Down Approach* (Kurose & Ross) and using the [TryHackMe](https://tryhackme.com) platform for hands-on exercises.

---