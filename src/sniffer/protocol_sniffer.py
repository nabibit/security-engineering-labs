#!/usr/bin/env python3
# Project: security-engineering-labs
# Purpose: Ethernet and ARP packet dissector – manually parse headers using byte offsets.
# Created: 2026-07-22

import scapy.all as scapy
import struct
import time

# Ethernet Header Offsets
# Ethernet header is exactly 14 bytes: 6 for Dest MAC, 6 for Src MAC, 2 for EtherType
ETH_DST_MAC_OFFSET = 0
ETH_SRC_MAC_OFFSET = 6
ETH_TYPE_OFFSET = 12
ETH_HEADER_LEN = 14

# ARP Header Offsets (Relative to the start of the ARP payload)
ARP_HW_TYPE_OFFSET = 0
ARP_PROTO_TYPE_OFFSET = 2
ARP_HW_LEN_OFFSET = 4
ARP_PROTO_LEN_OFFSET = 5
ARP_OPCODE_OFFSET = 6
ARP_SENDER_MAC_OFFSET = 8
ARP_SENDER_IP_OFFSET = 14
ARP_TARGET_MAC_OFFSET = 18
ARP_TARGET_IP_OFFSET = 24

# EtherType Constants
ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV4 = 0x0800

# ARP Opcodes
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2

def mac_to_str(mac_bytes: bytes) -> str:
    """Convert a 6-byte raw MAC address to a human-readable string (XX:XX:XX:XX:XX:XX)."""
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def ip_to_str(ip_bytes: bytes) -> str:
    """Convert a 4-byte raw IP address to a human-readable dotted decimal string."""
    return '.'.join(str(b) for b in ip_bytes)

def parse_ethernet(raw_bytes: bytes):
    """
    Manually slice the raw byte array to extract the Ethernet header fields.
    Returns a tuple of (dst_mac, src_mac, ethertype, payload).
    """
    dst_mac = mac_to_str(raw_bytes[ETH_DST_MAC_OFFSET:ETH_SRC_MAC_OFFSET])
    src_mac = mac_to_str(raw_bytes[ETH_SRC_MAC_OFFSET:ETH_TYPE_OFFSET])
    
    # Unpack 2 bytes as a network-byte-order unsigned short (!H)
    ethertype = struct.unpack('!H', raw_bytes[ETH_TYPE_OFFSET:ETH_HEADER_LEN])[0]
    
    # The rest of the bytes form the payload (ARP, IPv4, etc.)
    payload = raw_bytes[ETH_HEADER_LEN:]
    return dst_mac, src_mac, ethertype, payload

def parse_arp(payload: bytes):
    """
    Manually slice the ARP payload using struct unpacking to extract protocol metadata.
    Returns a dictionary of the parsed fields.
    """
    # An ARP packet over IPv4/Ethernet is 28 bytes long
    if len(payload) < 28:
        return None

    # Unpack 2-byte values (Hardware Type, Protocol Type, Opcode)
    hw_type = struct.unpack('!H', payload[ARP_HW_TYPE_OFFSET:ARP_PROTO_TYPE_OFFSET])[0]
    proto_type = struct.unpack('!H', payload[ARP_PROTO_TYPE_OFFSET:ARP_HW_LEN_OFFSET])[0]
    
    # Single byte values can be accessed directly
    hw_len = payload[ARP_HW_LEN_OFFSET]
    proto_len = payload[ARP_PROTO_LEN_OFFSET]
    opcode = struct.unpack('!H', payload[ARP_OPCODE_OFFSET:ARP_SENDER_MAC_OFFSET])[0]

    # Extract MACs and IPs
    sender_mac = mac_to_str(payload[ARP_SENDER_MAC_OFFSET:ARP_SENDER_IP_OFFSET])
    sender_ip = ip_to_str(payload[ARP_SENDER_IP_OFFSET:ARP_TARGET_MAC_OFFSET])
    target_mac = mac_to_str(payload[ARP_TARGET_MAC_OFFSET:ARP_TARGET_IP_OFFSET])
    target_ip = ip_to_str(payload[ARP_TARGET_IP_OFFSET:ARP_TARGET_IP_OFFSET+4])

    # Determine ARP operation
    op_str = "Request" if opcode == ARP_OP_REQUEST else ("Reply" if opcode == ARP_OP_REPLY else f"Unknown({opcode})")

    return {
        'hw_type': hw_type,
        'proto_type': hex(proto_type),
        'hw_len': hw_len,
        'proto_len': proto_len,
        'opcode': opcode,
        'opcode_str': op_str,
        'sender_mac': sender_mac,
        'sender_ip': sender_ip,
        'target_mac': target_mac,
        'target_ip': target_ip,
    }

def packet_callback(packet):
    """Callback triggered by Scapy for each sniffed packet to perform manual byte dissection."""
    raw_bytes = bytes(packet)

    print(f"\n[+] Packet captured at {time.strftime('%H:%M:%S')}")
    print(f"    Raw length: {len(raw_bytes)} bytes")

    # 1. Parse Ethernet header
    dst_mac, src_mac, ethertype, payload = parse_ethernet(raw_bytes)
    print(f"    Ethernet:")
    print(f"      Dest MAC: {dst_mac}")
    print(f"      Src MAC:  {src_mac}")
    print(f"      EtherType: 0x{ethertype:04x}")

    # 2. Check if it's an ARP packet and parse payload
    if ethertype == ETH_TYPE_ARP:
        print(f"    ARP Packet:")
        arp_data = parse_arp(payload)
        if arp_data:
            print(f"      Hardware Type: {arp_data['hw_type']} (Ethernet)")
            print(f"      Protocol Type: {arp_data['proto_type']} (IPv4)")
            print(f"      Hardware Len:  {arp_data['hw_len']}")
            print(f"      Protocol Len:  {arp_data['proto_len']}")
            print(f"      Opcode:        {arp_data['opcode']} ({arp_data['opcode_str']})")
            print(f"      Sender MAC:    {arp_data['sender_mac']}")
            print(f"      Sender IP:     {arp_data['sender_ip']}")
            print(f"      Target MAC:    {arp_data['target_mac']}")
            print(f"      Target IP:     {arp_data['target_ip']}")
        else:
            print(f"      [Invalid ARP packet]")
    else:
        print(f"    (Non-ARP packet – ignoring)")

def main():
    """Main execution function initiating the raw packet capture."""
    print("Starting Ethernet & ARP dissector...")
    print("Press Ctrl+C to stop.\n")

    try:
        # Sniff packets and route them to our manual parser
        scapy.sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[+] Dissector stopped by user.")

if __name__ == "__main__":
    main()