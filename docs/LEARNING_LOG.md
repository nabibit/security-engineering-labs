
# Learning Log – security-engineering-labs

*This log is a continuation of my daily progress documentation. Days 1–14 cover the development of my [Network Toolkit](https://github.com/nabibit/Network_Toolkit) and foundational networking concepts. Days 15–35 cover the [sysadmin-lab](https://github.com/nabibit/sysadmin-lab) project on OS internals and system monitoring. You can find those entries in the [sysadmin-lab LEARNING_LOG.md](https://github.com/nabibit/sysadmin-lab/blob/main/docs/LEARNING_LOG.md).*

---

## [2026-07-18] – Day 36: Live Sniffer & Hexdump

### Concept
- **Packet sniffing:** Capturing live network traffic using Scapy's `sniff()` function.
- **Hexdump:** A hexadecimal representation of raw bytes, showing each byte as two hex digits.
- **Packet structure:** Raw bytes on the wire consist of headers (Ethernet → IP → TCP/UDP/ICMP) and payload.
- **Scapy:** Uses `libpcap` (Linux) or `WinPcap`/`Npcap` (Windows) to tap into network interfaces.

### Artifact
- Completed TryHackMe Linux Unhatched Modules 1–4 and "What is Networking?" room.
- Created `src/sniffer/live_sniffer.py` – a Python script that:
  - Captures live packets using Scapy.
  - Displays packet length, timestamp, hexdump of first 64 bytes, ASCII representation, and Scapy summary.
  - Runs until 50 packets are captured or interrupted by the user.
- Tested the sniffer by generating traffic with `ping` and browsing the web.
- Completed OverTheWire Bandit Level 13 – used an SSH private key to authenticate as `bandit14` after copying the key to my local machine.

### Key Observations
- The `PermissionError` when running the sniffer indicated that raw packet capture requires root privileges – solved by using `sudo`.
- Scapy's `sniff()` captures packets and calls a callback function for each one.
- The hexdump shows the raw bytes of each packet, revealing protocol headers and payload.
- Bandit Level 13 taught me that localhost connections are blocked on OverTheWire; the solution was to copy the private key locally and connect externally.

### Reflection
This lab introduced me to the fundamentals of packet analysis. Seeing raw bytes in hex and ASCII format made the concept of network protocols tangible. The hexdump output shows exactly what travels across the wire – from Ethernet headers to TCP payloads. Understanding how to capture and interpret packets is essential for network security, troubleshooting, and protocol analysis. The Bandit CTF reinforced the importance of understanding SSH authentication methods and permission management.

### Evidence
- **Commits:**
  - `feat: add live sniffer with hexdump output`
  - `docs(ctf): add bandit level 13 writeup`
  - `docs: Day 36 – live sniffer and Scapy fundamentals + bandit level 13`

---