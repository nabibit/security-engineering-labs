#!/usr/bin/env python3
# Project: security-engineering-labs
# Purpose: Live packet sniffer that displays hexdump of raw bytes.
# Created: 2026-07-18

import scapy.all as scapy
import time

def packet_callback(packet):
    """Callback function for each sniffed packet."""
    print(f"\n[+] Captured packet at {time.strftime('%H:%M:%S')}")
    print(f"    Length: {len(packet)} bytes")
    print(f"    Raw data (hex):")
    # Show first 64 bytes as hex
    raw_bytes = bytes(packet)
    hexdump = ' '.join(f'{b:02x}' for b in raw_bytes[:64])
    print(f"    {hexdump}")
    
    # Show ascii representation (printable chars only)
    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_bytes[:64])
    print(f"    {ascii_repr}")
    
    # Show Scapy's summary (to verify what we see)
    print(f"    Scapy summary: {packet.summary()}")

def main():
    """Main sniffing function."""
    print("Starting live sniffer on all interfaces...")
    print("Press Ctrl+C to stop.")
    
    # Sniff packets and call the callback
    scapy.sniff(prn=packet_callback, store=False, count=50)

if __name__ == "__main__":
    main()