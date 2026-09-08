# VULN-001 PoC Notes: Off-by-One OOB Read in cbs_jpeg_split_fragment

## Vulnerability Summary

In `cbs_jpeg_split_fragment` (libavcodec/cbs_jpeg.c, lines 155-163), the boundary check
at line 155:
```c
if (length > frag->data_size - i) {   // allows length == data_size - i
```
allows `length == data_size - start` to pass. This causes:
```c
end = start + length;     // end == data_size
i = end;                  // i == data_size
frag->data[i] != 0xff     // OOB read at frag->data[data_size]  ← 1 byte past end
```

## PoC Approach

The crafted file `vuln_001_input.jpg` is a 6-byte minimal JPEG:
```
FF D8 FF FE 00 02
```
- `FF D8`: SOI marker
- `FF FE`: COM (comment) marker
- `00 02`: length = 2 (minimum; includes the 2 length bytes, 0 bytes of COM data)

Trace through `cbs_jpeg_split_fragment` with `data_size=6`:
- SOI found, next marker = 0xFE (COM), `start = 4`
- Non-SOS branch: `i = start = 4`
- Boundary check: `length (2) > data_size-i (6-4=2)` → `2 > 2` → **FALSE** (bug: allows it)
- `end = 4 + 2 = 6 = data_size`
- `i = end = 6`
- **OOB read**: `frag->data[6]` when valid indices are 0..5

## Trigger Path

```
ffmpeg -i vuln_001_input.jpg -f null -
  → avformat_open_input()
  → ff_cbs_read()
  → cbs_jpeg_split_fragment()   ← vulnerable function
```

## Expected vs. Observed Behavior

**Expected (per vulnerability description)**:
- In standard FFmpeg, `AV_INPUT_BUFFER_PADDING_SIZE=64` zero bytes are appended after
  I/O buffer allocations. The OOB read at `data[data_size]` hits a padding byte (0x00).
- Since 0x00 != 0xFF, `next_marker = -1`, terminating parsing early.
- ASAN in this scenario would NOT report an error because the padding bytes are within
  the same heap allocation (not truly out-of-bounds from allocator's perspective).
- Only without padding (custom allocator, or if the allocator places a guard page
  immediately after) would ASAN catch the read.

**Observed**:
- Status: `UNVERIFIED`
- The ffmpeg run produced: `[mjpeg @ ...] No JPEG data found in image`
- No ASAN heap-buffer-overflow error was reported.
- The standard `mjpeg` decoder (not the CBS-based path) was invoked for `.jpg` files
  via `image2` demuxer. The `cbs_jpeg_split_fragment` function is part of the CBS
  (Coded Bitstream) subsystem and is invoked via `ff_cbs_read()`, which may not be
  called in the standard `ffmpeg -i *.jpg` path for all decoder configurations.
- Without confirmation that `cbs_jpeg_split_fragment` was actually entered, the OOB
  read cannot be verified as triggered.

## Why UNVERIFIED

1. **Padding shields the crash**: Even if the CBS path was triggered, the 64-byte
   zero-padding appended by FFmpeg's I/O layer means the OOB byte is 0x00 from padding,
   not a true ASAN-detectable out-of-bounds. The behavior (next_marker=-1) is subtle.

2. **CBS path may not be triggered**: The `ffmpeg -i` path for JPEG images uses the
   standard mjpeg decoder, which may not invoke `ff_cbs_read()`. The CBS JPEG module
   is used in more specific contexts (e.g., JPEG-in-specific-containers or transcode
   scenarios that go through the CBS API).

3. **No ASAN report**: The ASAN-instrumented build (`-fsanitize=address,undefined`)
   produced no memory error, consistent with either (a) the path not being triggered,
   or (b) the OOB landing in the padding region.

## Conclusion

The logical vulnerability exists in the source code at the described location. The
off-by-one boundary check at line 155 is clearly incorrect. However, confirming
exploitation via `ffmpeg -i` on a plain `.jpg` file requires either (a) a path that
actually invokes `ff_cbs_read()` for the JPEG file, or (b) an ASAN build without
padding (e.g., using `av_malloc` replaced with bare `malloc` and a guard page).
