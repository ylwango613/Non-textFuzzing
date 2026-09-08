# VULN 002 – CWE-125 OOB Read in `cin_decode_huffman()` – PoC Notes

## Vulnerability Summary

**File**: `libavcodec/dsicinvideo.c`, lines 111 and 120  
**CWE**: CWE-125 (Out-of-bounds Read)

The `cin_decode_huffman()` main decode loop has two unprotected `*src++` accesses:

1. **Line 111** – when upper nibble of current byte is `0xF`, `huff_code = *src++` is executed without verifying `src < src_end`.  
2. **Line 120** – when lower nibble is `0xF`, `*dst_cur++ = *src++` similarly lacks the check.

When the last byte in the source buffer has upper or lower nibble equal to `0xF`, `src` reads one byte past the end of the heap allocation.

## PoC Approach

### File format construction (`vuln_002_gen.py`)

The CIN container (Delphine Software International) consists of:

| Section | Size | Key fields |
|---------|------|-----------|
| File header | 20 bytes | magic=`0x55AA0000`, audio_frequency=22050, audio_bits=16 (required by probe) |
| Frame header | 16 bytes | video_frame_type=35, pal_colors_count=0, video_frame_size=16, magic=`0xAA55AA55` |
| Video payload | 16 bytes | 15-byte huffman table + 1 trigger byte |

### Trigger mechanism

With `video_frame_type=35`, `cinvideo_decode_frame()` calls:
```c
cin_decode_huffman(buf, bitmap_frame_size=16, ...)
```

Inside `cin_decode_huffman()`:
1. First 15 bytes are consumed as the huffman code table (`memcpy + src += 15`).
2. `src_end = src_orig + 16`, so after the 15-byte skip, `src = src_orig + 15 < src_end` – the loop iterates once.
3. `huff_code = *src++` reads byte 15 (valid) → `huff_code = 0xF0`.
4. `(huff_code >> 4) == 0xF` is true → **line 111**: `huff_code = *src++` executes with `src = src_orig + 16 = src_end` → **1-byte OOB read past heap allocation**.

The trigger byte `0xF0` is chosen so that only the line-111 path is exercised (upper nibble `0xF`, lower nibble `0`).

### Why these field values

- `video_frame_size=16`: satisfies `src_size >= 15` (needed to pass the `memcpy`) and leaves exactly 1 byte for the decode loop trigger.
- `pal_colors_count=0`: no palette bytes emitted, so the 16 raw video bytes are passed directly to the decoder without any offset adjustment.
- `video_frame_width=4, video_frame_height=4`: gives `bitmap_size = 16`, satisfying allocation checks.
- `audio_frame_size=0`: no audio payload required; keeps the file minimal.

## Expected Output

With an ASan-instrumented build the result should show:
```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 1 at ...
in cin_decode_huffman libavcodec/dsicinvideo.c:111
```

Without ASan the read silently returns whatever byte follows the heap allocation; no crash occurs, but the memory access is undefined behaviour.
