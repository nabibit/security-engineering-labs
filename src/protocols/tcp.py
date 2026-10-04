#!/usr/bin/env python3
"""
Project: security-engineering-labs
Purpose: TCP header dissector - manually parse TCP headers (RFC 793).
Created: 2026-10-04
"""

import struct

# TCP flag bitmasks
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

def dissect_tcp(raw_bytes: bytes) -> dict:
    """
    Dissect a TCP header from raw bytes.

    Args:
        raw_bytes: Raw bytes of the TCP header (at least 20 bytes).

    Returns:
        dict: Parsed TCP header fields including flags, length, and payload.
    """
    if len(raw_bytes) < 20:
        raise ValueError(f"TCP header too short: {len(raw_bytes)} bytes (need 20)")

    src_port = struct.unpack('!H', raw_bytes[0:2])[0]
    dest_port = struct.unpack('!H', raw_bytes[2:4])[0]
    seq = struct.unpack('!I', raw_bytes[4:8])[0]
    ack = struct.unpack('!I', raw_bytes[8:12])[0]

    # Data offset is the high 4 bits of byte 12
    data_offset_byte = struct.unpack('!B', raw_bytes[12:13])[0]
    data_offset = data_offset_byte >> 4
    header_len = data_offset * 4

    # Flags are the low 8 bits of byte 13 (plus 1 bit from byte 12 - ignore NS for now)
    flags = struct.unpack('!B', raw_bytes[13:14])[0]

    window = struct.unpack('!H', raw_bytes[14:16])[0]
    checksum = struct.unpack('!H', raw_bytes[16:18])[0]
    urgent = struct.unpack('!H', raw_bytes[18:20])[0]

    # Decode flag names
    flag_names = []
    if flags & TCP_FIN: flag_names.append('FIN')
    if flags & TCP_SYN: flag_names.append('SYN')
    if flags & TCP_RST: flag_names.append('RST')
    if flags & TCP_PSH: flag_names.append('PSH')
    if flags & TCP_ACK: flag_names.append('ACK')
    if flags & TCP_URG: flag_names.append('URG')
    if flags & TCP_ECE: flag_names.append('ECE')
    if flags & TCP_CWR: flag_names.append('CWR')

    # Payload starts after the header (accounting for options)
    payload = raw_bytes[header_len:]

    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'seq': seq,
        'ack': ack,
        'data_offset': data_offset,
        'header_len': header_len,
        'flags': flags,
        'flag_names': flag_names,
        'window': window,
        'checksum': checksum,
        'urgent': urgent,
        'payload': payload,
    }

def port_to_service(port: int) -> str:
    """Convert port number to common TCP service name."""
    services = {
        20: 'FTP-Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        3306: 'MySQL',
        3389: 'RDP',
    }
    return services.get(port, f'Unknown({port})')

if __name__ == "__main__":
    print("TCP dissector module - import and use in packet_dissector.py")