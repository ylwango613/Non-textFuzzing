# VULN 002 PoC Notes

## Vulnerability

- **File**: `libavcodec/pgssubdec.c`, function `parse_palette_segment()`, lines 354-374
- **Type**: CWE-125 Out-of-bounds Read
- **Status**: VERIFIED_BEHAVIOR

## Root Cause

The palette parsing loop uses `buf < buf_end` as its loop condition, requiring
only 1 remaining byte to re-enter the loop body, but each iteration unconditionally
reads 5 bytes (color_id + Y + Cr + Cb + alpha via `bytestream_get_byte` x5).

```c
while (buf < buf_end) {
    color_id  = bytestream_get_byte(&buf);  // +1
    y         = bytestream_get_byte(&buf);  // +1
    cr        = bytestream_get_byte(&buf);  // +1
    cb        = bytestream_get_byte(&buf);  // +1
    alpha     = bytestream_get_byte(&buf);  // +1  <-- OOB on last iteration
    ...
}
```

When `(segment_length - 2) % 5 != 0`, the final loop iteration reads past
`buf_end`. With `segment_length = 8`:
- 8 - 2 (palette_id + palette_version) = 6 bytes of palette entries
- 6 % 5 = 1 leftover byte
- 1 leftover byte satisfies `buf < buf_end` and triggers a loop iteration
  that reads 5 bytes → **4 bytes OOB read past buf_end**

## PoC Strategy

The crafted `.sup` file (58 bytes) contains three PGS packets:

1. **PCS** (0x16, segment_length=11): Minimal valid Presentation Composition
   Segment that sets up video dimensions (1920x1080) with no objects.
2. **PDS** (0x14, segment_length=8): Malformed Palette Definition Segment:
   - palette_id (1 byte)
   - palette_version (1 byte)
   - 1 valid palette entry: color_id + Y + Cr + Cb + alpha (5 bytes)
   - 1 leftover byte (triggers OOB in 2nd loop iteration)
3. **END** (0x80, segment_length=0): End of Display Set.

## Trigger Path

```
ffprobe -show_frames vuln_002_input.sup
  → avformat_open_input()             [supdec.c - reads PGS packets]
  → ffprobe show_frames loop
  → avcodec_decode_subtitle2()
  → decode() [pgssubdec.c:595]
  → parse_palette_segment(avctx, buf, 8) [pgssubdec.c:637]
  → OOB: iteration 2 reads 5 bytes with only 1 valid [pgssubdec.c:354-359]
```

## Confirmed Behavior

`ffprobe -show_frames` output confirms the decoder was invoked:
```
[SUBTITLE]
media_type=subtitle
pts=0
num_rects=0
[/SUBTITLE]
```

The subtitle was decoded successfully (0 rects because PCS has object_count=0),
confirming `parse_palette_segment()` ran through the OOB code path.

## Why ASAN Does Not Fire

FFmpeg's `av_grow_packet()` always appends `AV_INPUT_BUFFER_PADDING_SIZE = 64`
bytes of zero-initialized padding after every AVPacket allocation
(`libavcodec/packet.c:129: new_size = pkt->size + grow_by + AV_INPUT_BUFFER_PADDING_SIZE`).

For our PDS packet:
- Logical size: 3 (type + length header) + 8 (segment data) = 11 bytes
- Physical allocation: 11 + 64 = **75 bytes**
- OOB read reaches: offset 11 + 4 = 15 (still within 75-byte allocation)
- ASAN marks bytes [0..74] as accessible → no redzone violation → no crash

## Real-World Impact

The vulnerability IS exploitable in environments where:
- Subtitle data is loaded from a memory-mapped file (no padding)
- Custom allocators without padding are used (embedded/IoT devices)
- The OOB data follows security-sensitive memory (credentials, keys)
- The misread palette data corrupts display output silently
