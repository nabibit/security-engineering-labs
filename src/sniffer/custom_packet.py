#!/usr/bin/env python3
# Project: security-engineering-labs
# Purpose: Craft and send custom ICMP Echo Request packets with manual checksum calculation.
# Created: 2026-07-31

import sys
import time
from scapy.all import IP, ICMP, sr1

def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the ICMP checksum manually (RFC 792).
    The checksum is the 16-bit one's complement of the one's complement
    sum of the ICMP header and data, with the checksum field initially set to 0.
    """
    # Pad to even length if necessary
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
        # Carry wrap-around
        checksum = (checksum & 0xffff) + (checksum >> 16)

    return ~checksum & 0xffff

def build_icmp_echo(dest_ip: str, icmp_id: int = 12345, seq: int = 1, payload: bytes = None) -> bytes:
    """
    Build a custom ICMP Echo Request packet with manual checksum calculation.

    Returns:
        bytes: The complete raw packet (IP header + ICMP header + payload).
    """
    if payload is None:
        payload = b"Hello from custom ICMP!"

    # Build the IP layer
    ip = IP(dst=dest_ip)

    # Build ICMP layer with checksum = 0 initially
    icmp = ICMP(type=8, code=0, id=icmp_id, seq=seq, chksum=0)

    # Build the packet and get raw bytes
    packet = ip / icmp / payload
    raw_packet = bytes(packet)

    # Find where the ICMP header starts (after IP header)
    ip_header_len = (raw_packet[0] & 0x0F) * 4
    icmp_start = ip_header_len

    # Extract ICMP header (first 8 bytes) and payload
    icmp_header = raw_packet[icmp_start:icmp_start+8]
    icmp_data = raw_packet[icmp_start+8:]

    # Zero out the checksum field (bytes 2-3 of ICMP header)
    icmp_header = icmp_header[:2] + b'\x00\x00' + icmp_header[4:]

    # Calculate checksum over ICMP header + payload
    checksum_packet = icmp_header + icmp_data
    valid_checksum = calculate_icmp_checksum(checksum_packet)

    # Build the final ICMP layer with correct checksum
    icmp_final = ICMP(type=8, code=0, id=icmp_id, seq=seq, chksum=valid_checksum)

    # Return the complete packet as bytes
    return bytes(ip / icmp_final / payload)

def send_custom_ping(dest_ip: str, count: int = 1, timeout: int = 2) -> list:
    """Send custom ICMP Echo Request packets and wait for replies."""
    replies = []
    print(f"[*] Sending {count} custom ICMP Echo Request(s) to {dest_ip}...")

    for i in range(count):
        seq = i + 1
        # Build the packet using Scapy
        packet = IP(dst=dest_ip) / ICMP(type=8, code=0, id=12345, seq=seq) / b"Custom ping!"

        try:
            reply = sr1(packet, timeout=timeout, verbose=False)
            if reply:
                replies.append(reply)
                print(f"[+] Reply received (seq={seq})")
            else:
                print(f"[-] No reply (seq={seq})")
        except Exception as e:
            print(f"[!] Error transmitting packet: {e}")

        time.sleep(0.5)

    return replies

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 custom_packet.py <destination_ip> [count]")
        print("Example: sudo python3 custom_packet.py 8.8.8.8 3")
        sys.exit(1)

    dest_ip = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1

    print("=" * 60)
    print("CUSTOM ICMP ECHO REQUEST (PING)")
    print("=" * 60)

    replies = send_custom_ping(dest_ip, count)

    print("\n" + "=" * 60)
    print(f"[*] Summary: {len(replies)}/{count} replies received")
    print("=" * 60)

    for idx, reply in enumerate(replies):
        print(f"\n[+] Reply {idx+1} Details:")
        reply.show()

if __name__ == "__main__":
    main()