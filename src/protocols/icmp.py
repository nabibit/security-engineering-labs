#!/usr/bin/env python3
# Project: security-engineering-labs
# Purpose: ICMP header dissector – manually parse ICMP headers according to RFC 792.
# Created: 2026-07-27

import struct

# ICMP Type Constants
ICMP_TYPE_ECHO_REPLY = 0
ICMP_TYPE_DEST_UNREACHABLE = 3
ICMP_TYPE_ECHO_REQUEST = 8
ICMP_TYPE_TIME_EXCEEDED = 11

def dissect_icmp(raw_bytes: bytes) -> dict:
    """
    Manually dissect an ICMP header from raw bytes.
    
    Args:
        raw_bytes (bytes): Raw byte payload starting at the ICMP header (minimum 4 bytes).
        
    Returns:
        dict: A dictionary containing parsed ICMP fields (type, code, checksum, payload).
    """
    # Minimum ICMP header is 4 bytes (Type, Code, Checksum)
    if len(raw_bytes) < 4:
        raise ValueError(f"Payload too short for an ICMP header: {len(raw_bytes)} bytes (< 4 bytes).")

    # Byte 0: ICMP Message Type (e.g., 8 for Echo Request, 0 for Echo Reply)
    icmp_type = struct.unpack('!B', raw_bytes[0:1])[0]
    
    # Byte 1: Sub-type Code (usually 0 for standard Echo messages)
    code = struct.unpack('!B', raw_bytes[1:2])[0]
    
    # Bytes 2-3: Header and data Checksum
    checksum = struct.unpack('!H', raw_bytes[2:4])[0]

    return {
        'type': icmp_type,
        'code': code,
        'checksum': checksum,
        'payload': raw_bytes[4:],
    }

def icmp_type_to_str(icmp_type: int) -> str:
    """Convert an ICMP type integer into its standard RFC 792 human-readable name."""
    types = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        4: 'Source Quench',
        5: 'Redirect',
        8: 'Echo Request',
        11: 'Time Exceeded',
        12: 'Parameter Problem',
        13: 'Timestamp Request',
        14: 'Timestamp Reply',
    }
    return types.get(icmp_type, f'Unknown({icmp_type})')

if __name__ == "__main__":
    print("ICMP dissector module – import and use inside protocol_sniffer.py")