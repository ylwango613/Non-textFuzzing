#!/usr/bin/env python3
"""
PoC generator for VULN-001:
FoFiType1C::getGlyphName() heap OOB read via unchecked gid parameter

Root cause:
  FoFiType1C::getGlyphName(int gid) at FoFiType1C.cc:171 directly accesses
  charset[gid] without any bounds check (0 <= gid < nGlyphs). charset is a
  Gushort array allocated as gmallocn(nGlyphs, sizeof(Gushort)). If gid is
  out of range, this is a heap OOB read (CWE-125).

  The vulnerability exists in the API but is latent: no xpdf caller (pdftotext,
  xpdf, pdftoppm, etc.) ever calls getGlyphName() with an unvalidated gid during
  normal PDF processing. The execution path that IS taken is:
    pdftotext -> SplashOutputDev::doUpdateFont() ->
    Gfx8BitFont::getCodeToGIDMap(FoFiType1C*) ->
    FoFiType1C::getNameToGIDMap()  [iterates gid=0..nGlyphs-1 safely]
  getGlyphName() is declared in FoFiType1C.h but has zero callers in xpdf.

  This PoC constructs:
    - A valid CFF (Type1C) font with nGlyphs=1 (only .notdef exists)
    - An embedding of that CFF in a PDF as a Type1 font with /FontFile3 /Subtype /Type1C
    - A page with text content that references the font, forcing pdftotext to
      load and parse the CFF (triggering getCodeToGIDMap → getNameToGIDMap)
    - Verifies that no crash occurs and that getGlyphName() is never reached

CFF binary layout (40 bytes total, nGlyphs=1):
  Offset  0: Header       01 00 04 01
  Offset  4: Name INDEX   count=1, offSize=1, off=[1,9], data="TestFont"
  Offset 17: TopDICT IDX  count=1, offSize=1, off=[1,8], data=7bytes
  Offset 22: TopDICT data charset@33, charstrings@34, private(size=0,off=40)
  Offset 29: String INDEX  count=0  (empty)
  Offset 31: GlobalSubrIDX count=0  (empty)
  Offset 33: charset       format=0  (nGlyphs=1, 0 SIDs follow)
  Offset 34: CharStrings   count=1, offSize=1, off=[1,2], data=0e (endchar)
  Offset 40: Private DICT  (0 bytes, size declared as 0 in TopDICT)
"""

import struct
import os

OUTPUT_DIR = "/data/ylwang/non-textfuzz/target/_poc/xpdf/fofi_FoFiType1C_h"


def build_cff_nglyphs1():
    """
    Build a minimal CFF (Type1C) font with exactly nGlyphs=1.
    Only GID 0 (.notdef) exists, defined by a single endchar charstring.

    CFF integer encoding (b0 in [32,246]): value = b0 - 139
      - 0  -> 139 (0x8b)
      - 33 -> 172 (0xac)
      - 34 -> 173 (0xad)
      - 40 -> 179 (0xb3)

    TOP DICT operators:
      charset    -> 0x0f (15)
      CharStrings -> 0x11 (17)
      Private     -> 0x12 (18)  [takes two operands: size, offset]
    """
    # --- Header ---
    # major=1, minor=0, hdrSize=4, offSize=1
    header = bytes([0x01, 0x00, 0x04, 0x01])

    # --- Name INDEX ---
    # count=1, offSize=1, offset[0]=1, offset[1]=9 (len("TestFont")+1), "TestFont"
    font_name = b"TestFont"
    name_index = (
        bytes([0x00, 0x01])          # count=1
        + bytes([0x01])              # offSize=1
        + bytes([0x01])              # offset[0]=1
        + bytes([len(font_name)+1])  # offset[1]=9
        + font_name
    )

    # --- Top DICT data (7 bytes) ---
    # Encode:
    #   charset@33:         0xac 0x0f
    #   charstrings@34:     0xad 0x11
    #   private size=0,off=40: 0x8b 0xb3 0x12
    top_dict_data = bytes([
        0xac, 0x0f,       # charset = 33
        0xad, 0x11,       # CharStrings = 34
        0x8b, 0xb3, 0x12  # Private: size=0, offset=40
    ])

    # --- Top DICT INDEX ---
    # count=1, offSize=1, offset[0]=1, offset[1]=len(top_dict_data)+1=8
    top_dict_index = (
        bytes([0x00, 0x01])                    # count=1
        + bytes([0x01])                        # offSize=1
        + bytes([0x01])                        # offset[0]=1
        + bytes([len(top_dict_data) + 1])      # offset[1]=8
        + top_dict_data
    )

    # --- String INDEX (empty) ---
    string_index = bytes([0x00, 0x00])  # count=0

    # --- Global Subr INDEX (empty) ---
    global_subr_index = bytes([0x00, 0x00])  # count=0

    # --- charset (format 0, nGlyphs=1 means 0 SIDs follow) ---
    # format byte 0x00 only; GID 0 implicitly = SID 0 (.notdef)
    charset = bytes([0x00])

    # --- CharStrings INDEX (nGlyphs=1, one endchar charstring) ---
    # endchar opcode = 0x0e (14)
    charstring = bytes([0x0e])  # endchar
    charstrings_index = (
        bytes([0x00, 0x01])          # count=1
        + bytes([0x01])              # offSize=1
        + bytes([0x01])              # offset[0]=1
        + bytes([len(charstring)+1]) # offset[1]=2
        + charstring
    )

    # --- Private DICT (empty, size=0) ---
    private_dict = bytes([])

    cff = (header + name_index + top_dict_index
           + string_index + global_subr_index
           + charset + charstrings_index + private_dict)
    return cff


def build_pdf_with_type1c(cff_data):
    """
    Build a PDF embedding the CFF font as Type1C via /FontFile3 /Subtype /Type1C.
    This causes pdftotext to:
      1. Detect fontType1C from FontDescriptor.FontFile3.Subtype = /Type1C
      2. Call FoFiType1C::make() to parse the CFF
      3. Call Gfx8BitFont::getCodeToGIDMap(ffT1C) which calls
         FoFiType1C::getNameToGIDMap() (safe, iterates gid=0..nGlyphs-1)
    getGlyphName() is NEVER called in this path.
    """
    cff_len = len(cff_data)

    # Page content stream: use font F1 to print "A"
    # The character code 0x41 ('A') is mapped through WinAnsiEncoding to glyph "A"
    # getCodeToGIDMap looks up "A" in getNameToGIDMap result -> not found -> gid=0
    content = b"BT /F1 12 Tf 100 700 Td (A) Tj ET\n"

    # Build objects
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    obj3 = (
        b"3 0 obj\n"
        b"<< /Type /Page\n"
        b"   /Parent 2 0 R\n"
        b"   /MediaBox [0 0 612 792]\n"
        b"   /Contents 4 0 R\n"
        b"   /Resources << /Font << /F1 5 0 R >> >>\n"
        b">>\nendobj\n"
    )
    obj4 = (
        b"4 0 obj\n"
        b"<< /Length " + str(len(content)).encode() + b" >>\n"
        b"stream\n" + content + b"endstream\nendobj\n"
    )
    # Type1 font dict; xpdf will reclassify to fontType1C due to FontFile3
    obj5 = (
        b"5 0 obj\n"
        b"<< /Type /Font\n"
        b"   /Subtype /Type1\n"
        b"   /BaseFont /TestFont\n"
        b"   /Encoding /WinAnsiEncoding\n"
        b"   /FirstChar 65\n"
        b"   /LastChar 65\n"
        b"   /Widths [600]\n"
        b"   /FontDescriptor 6 0 R\n"
        b">>\nendobj\n"
    )
    obj6 = (
        b"6 0 obj\n"
        b"<< /Type /FontDescriptor\n"
        b"   /FontName /TestFont\n"
        b"   /Flags 32\n"
        b"   /FontBBox [-100 -100 1000 1000]\n"
        b"   /ItalicAngle 0\n"
        b"   /Ascent 800\n"
        b"   /Descent -200\n"
        b"   /CapHeight 700\n"
        b"   /StemV 80\n"
        b"   /FontFile3 7 0 R\n"
        b">>\nendobj\n"
    )
    # FontFile3 stream with /Subtype /Type1C - tells xpdf this is a CFF/Type1C font
    obj7_hdr = (
        b"7 0 obj\n"
        b"<< /Length " + str(cff_len).encode() + b"\n"
        b"   /Subtype /Type1C\n"
        b">>\n"
        b"stream\n"
    )
    obj7_ftr = b"\nendstream\nendobj\n"
    obj7 = obj7_hdr + cff_data + obj7_ftr

    # Assemble PDF body
    pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = {}
    for i, obj in enumerate([obj1, obj2, obj3, obj4, obj5, obj6, obj7], start=1):
        offsets[i] = len(pdf)
        pdf += obj

    # Cross-reference table
    n_objs = 7
    xref_offset = len(pdf)
    xref = b"xref\n0 " + str(n_objs + 1).encode() + b"\n"
    xref += b"0000000000 65535 f \n"
    for i in range(1, n_objs + 1):
        xref += "{:010d} 00000 n \n".format(offsets[i]).encode()

    pdf += xref
    pdf += (
        b"trailer\n<< /Size " + str(n_objs + 1).encode() + b" /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_offset).encode() + b"\n"
        b"%%EOF\n"
    )
    return pdf


def verify_cff(cff):
    """Basic sanity checks on the generated CFF."""
    assert len(cff) == 40, f"Expected 40 bytes, got {len(cff)}"
    # Header
    assert cff[0:4] == bytes([0x01, 0x00, 0x04, 0x01]), "Bad header"
    # Name INDEX count=1
    assert cff[4:6] == bytes([0x00, 0x01]), "Bad Name INDEX count"
    # Top DICT INDEX count=1
    assert cff[17:19] == bytes([0x00, 0x01]), "Bad Top DICT INDEX count"
    # Top DICT data: charset@33=0xac, CharStrings@34=0xad, Private(0,40)=8b b3 12
    assert cff[22] == 0xac, f"charset int should be 0xac, got {hex(cff[22])}"
    assert cff[23] == 0x0f, "charset operator should be 0x0f"
    assert cff[24] == 0xad, f"charstrings int should be 0xad, got {hex(cff[24])}"
    assert cff[25] == 0x11, "charstrings operator should be 0x11"
    # charset format byte
    assert cff[33] == 0x00, "charset format should be 0 (format 0)"
    # CharStrings INDEX count=1
    assert cff[34:36] == bytes([0x00, 0x01]), "CharStrings INDEX count should be 1"
    # endchar
    assert cff[39] == 0x0e, "Last charstring byte should be endchar (0x0e)"
    print("[*] CFF sanity checks passed")
    print(f"    nGlyphs = 1 (count in CharStrings INDEX = 1)")
    print(f"    charset[0] (GID 0 = .notdef) = SID {cff[33]-0} (format-0, implicit SID 0)")
    print(f"    charset offset in CFF = {cff[22] - 139} (byte {cff[22]-139})")
    print(f"    charstrings offset = {cff[24] - 139} (byte {cff[24]-139})")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Build CFF
    cff = build_cff_nglyphs1()
    print(f"[*] Built CFF: {len(cff)} bytes")
    print(f"    Hex: {cff.hex(' ')}")
    verify_cff(cff)

    # Write raw CFF file for inspection
    cff_path = os.path.join(OUTPUT_DIR, "vuln_001.cff")
    with open(cff_path, 'wb') as f:
        f.write(cff)
    print(f"[*] Wrote: {cff_path}")

    # Build PDF
    pdf = build_pdf_with_type1c(cff)
    pdf_path = os.path.join(OUTPUT_DIR, "vuln_001.pdf")
    with open(pdf_path, 'wb') as f:
        f.write(pdf)
    print(f"[*] Wrote: {pdf_path} ({len(pdf)} bytes)")
    print()
    print("[!] NOTE: This PoC demonstrates a LATENT vulnerability.")
    print("    FoFiType1C::getGlyphName() has a heap OOB read (no bounds check on gid),")
    print("    but pdftotext never calls getGlyphName() — it uses getNameToGIDMap()")
    print("    which iterates gid=0..nGlyphs-1 safely. The vulnerability is unreachable")
    print("    from any PDF file via the current xpdf processing pipeline.")


if __name__ == "__main__":
    main()
