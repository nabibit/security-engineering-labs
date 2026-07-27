#!/usr/bin/env python3
# Project: security-engineering-labs
# Purpose: IPv4 header dissector – manually parse IPv4 headers (RFC 791) using byte offsets.
# Created: 2026-07-24
# Updated: 2026-07-27 (Added get_payload_offset helper function for Layer 4 slicing)

import struct
import socket

def dissect_ipv4(raw_bytes: bytes) -> dict:
    """
    Manually dissect an IPv4 header from raw bytes according to RFC 791.
    
    Args:
        raw_bytes (bytes): Raw byte payload starting at the IPv4 header (minimum 20 bytes).
        
    Returns:
        dict: A dictionary containing parsed IPv4 fields (version, ihl, total_len, ttl, protocol, src_ip, dest_ip).
    """
    # Ensure we have at least the minimum 20 bytes of an IPv4 header
    if len(raw_bytes) < 20:
        raise ValueError("Packet payload too short for an IPv4 header (< 20 bytes).")

    # Byte 0: Version (higher 4 bits) and Internet Header Length / IHL (lower 4 bits)
    version_ihl = struct.unpack('!B', raw_bytes[0:1])[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    
    # IHL counts the number of 32-bit words. Multiply by 4 to get the header length in bytes.
    header_len = ihl * 4

    # Bytes 2-3: Total Length of the packet (Header + Payload) in bytes
    total_len = struct.unpack('!H', raw_bytes[2:4])[0]

    # Byte 8: Time to Live (TTL) - maximum router hops before packet is dropped
    ttl = struct.unpack('!B', raw_bytes[8:9])[0]

    # Byte 9: Protocol - indicates the transport layer protocol (e.g., 1=ICMP, 6=TCP, 17=UDP)
    protocol = struct.unpack('!B', raw_bytes[9:10])[0]

    # Bytes 12-15: Source IPv4 Address (4 bytes)
    src_ip = socket.inet_ntoa(raw_bytes[12:16])

    # Bytes 16-19: Destination IPv4 Address (4 bytes)
    dest_ip = socket.inet_ntoa(raw_bytes[16:20])

    return {
        'version': version,
        'ihl': ihl,
        'header_len': header_len,
        'total_len': total_len,
        'ttl': ttl,
        'protocol': protocol,
        'src_ip': src_ip,
        'dest_ip': dest_ip,
    }

def protocol_to_str(protocol: int) -> str:
    """Convert a numeric IP protocol identifier into its standard human-readable name."""
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        89: 'OSPF',
    }
    return protocols.get(protocol, f'Unknown({protocol})')

def get_payload_offset(raw_bytes: bytes) -> int:
    """Calculate and return the exact byte offset where the upper-layer payload begins."""
    version_ihl = struct.unpack('!B', raw_bytes[0:1])[0]
    ihl = version_ihl & 0x0F
    return ihl * 4

if __name__ == "__main__":
    print("IPv4 dissector module – import and use inside packet_dissector.py")