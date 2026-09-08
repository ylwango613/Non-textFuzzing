# VULN 001 – CWE-125 Out-of-bounds Read in cin_decode_huffman()

## Vulnerable code
`libavcodec/dsicinvideo.c`, lines 104-105:
```c
memcpy(huff_code_table, src, 15);   // always copies 15 bytes
src += 15;                           // no src_size >= 15 guard
```

## Root cause
`cin_decode_huffman()` never checks that `src_size >= 15` before the unconditional
`memcpy`. When called with `src_size=0`, the function reads 15 bytes beyond the
end of the heap buffer.

## Trigger chain
1. **Crafted .cin file** sets `video_frame_size=0` and `pal_colors_count=0` in the
   per-frame header and `video_frame_type=35` in the same header.
2. **Demuxer** (`libavformat/dsicin.c`, `cin_read_packet`):
   - `pkt_size = (palette_type + 3) * pal_colors_count + video_frame_size`
     = `(0+3)*0 + 0 = 0`
   - `av_new_packet(pkt, 4 + 0)` → allocates a 4-byte heap buffer
   - First 4 bytes are the header fields; no actual video payload is appended.
3. **Decoder** (`cinvideo_decode_frame`):
   - `buf += 4` → pointer moves past header, `bitmap_frame_size = buf_size - 4 = 0`
   - `bitmap_frame_type == 35` → calls
     `cin_decode_huffman(buf, bitmap_frame_size=0, ...)`
4. **OOB read**: `memcpy(huff_code_table, src, 15)` reads 15 bytes from a
   zero-length region, accessing heap memory beyond the packet buffer.

## PoC approach
`vuln_001_gen.py` constructs a minimal valid CIN file:
- **File header** (20 bytes): passes the demuxer probe checks
  (`audio_frequency=22050`, `audio_bits=16`, `audio_stereo=0`).
- **Frame header** (16 bytes): `video_frame_type=35`, `pal_colors_count=0`,
  `video_frame_size=0`, plus the required `0xAA55AA55` trailer word.
- **Audio payload** (100 bytes): satisfies the subsequent audio read_packet call
  so ffmpeg does not stall before decoding the video frame.

## Expected evidence
Under AddressSanitizer: `heap-buffer-overflow` READ of size 15 at the
`memcpy` site in `cin_decode_huffman`, with the packet buffer allocated by
`av_new_packet` shown in the allocation trace.
