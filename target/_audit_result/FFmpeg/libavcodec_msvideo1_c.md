**Analysis summary — key checks performed:**

**1. Stream bounds (`CHECK_STREAM_PTR` macro):**
Every read from `s->buf` is guarded by `CHECK_STREAM_PTR(n)` which tests `stream_ptr + n > s->size` and `return`s on violation. All byte reads (lines 126–155, 226–259) are properly guarded. No OOB read path.

**2. Pixel pointer bounds (8-bit and 16-bit):**
- `block_ptr = ((block_y * 4) - 1) * stride`. For `block_y` from `blocks_high` down to 1, the maximum pixel index reached is `(height−1)×stride + (width−1)`, which equals the last byte of the allocated frame (`height × stride − 1`). Minimum pixel index is 0 (when `block_y=1`, row 3 of the 4×4 block). No out-of-bounds.
- After the last pixel_y iteration the `pixel_ptr -= row_dec` makes pixel_ptr negative, but pixel_ptr is re-assigned `= block_ptr` at the start of every block and is not used after the row loop. No write to a negative index.

**3. `colors[]` array index:**
In 8-color mode: `((pixel_y & 0x2) << 1) + (pixel_x & 0x2) + ((flags & 0x1) ^ 1)` → max = 4 + 2 + 1 = **7**. Array size = 8. No OOB.

**4. Palette `memcpy` (line 72):**
`memcpy(s->pal, avctx->extradata, AVPALETTE_SIZE)` is guarded by `if (avctx->extradata_size >= AVPALETTE_SIZE)`. `s->pal` is exactly `AVPALETTE_SIZE` (1024) bytes. No overflow.

**5. `skip_blocks` underflow (skip code):**
When `byte_b=0x84` and `byte_a=0`, `skip_blocks = -1`. All subsequent blocks enter the skip path, but the outer loops still terminate after `blocks_wide × blocks_high` iterations. This is a functional correctness bug, not a memory-safety bug.

**6. `CHECK_STREAM_PTR` signed integer overflow:**
Theoretically, if `s->size ≈ INT_MAX` and `stream_ptr + n` wraps to negative, the check passes incorrectly. This requires a ~2 GB packet, which FFmpeg and OS resource limits make practically impossible.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
