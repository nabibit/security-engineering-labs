#!/usr/bin/env python3
# Project: security-engineering-labs
# Purpose: UDP header dissector – manually parse UDP headers according to RFC 768.
# Created: 2026-07-27

import struct

def dissect_udp(raw_bytes: bytes) -> dict:
    """
    Manually dissect a UDP header from raw bytes.
    
    Args:
        raw_bytes (bytes): Raw byte payload starting at the UDP header (minimum 8 bytes).
        
    Returns:
        dict: A dictionary containing parsed UDP fields (src_port, dest_port, length, checksum).
    """
    # UDP header is exactly 8 bytes long (4 fields of 2 bytes each)
    if len(raw_bytes) < 8:
        raise ValueError(f"Payload too short for a UDP header: {len(raw_bytes)} bytes (< 8 bytes).")

    # Bytes 0-1: Source Port (16-bit unsigned short)
    src_port = struct.unpack('!H', raw_bytes[0:2])[0]
    
    # Bytes 2-3: Destination Port (16-bit unsigned short)
    dest_port = struct.unpack('!H', raw_bytes[2:4])[0]
    
    # Bytes 4-5: Length of UDP header and data in bytes (minimum 8)
    length = struct.unpack('!H', raw_bytes[4:6])[0]
    
    # Bytes 6-7: Checksum (optional in IPv4, mandatory in IPv6)
    checksum = struct.unpack('!H', raw_bytes[6:8])[0]

    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'length': length,
        'checksum': checksum,
    }

def port_to_service(port: int) -> str:
    """Map standard UDP network ports to their common service names."""
    services = {
        53: 'DNS',
        67: 'DHCP Server',
        68: 'DHCP Client',
        69: 'TFTP',
        123: 'NTP',
        161: 'SNMP',
        514: 'Syslog',
        520: 'RIP',
    }
    return services.get(port, f'Unknown({port})')

if __name__ == "__main__":
    print("UDP dissector module – import and use inside protocol_sniffer.py")