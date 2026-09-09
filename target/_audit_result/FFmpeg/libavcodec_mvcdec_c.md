After reading the complete file and tracing all related APIs (`ff_set_dimensions` → `av_image_check_size2`, bytestream accessors, frame writes), I've completed the full analysis:

**Findings summary:**

1. **`mvc_decode_init` (lines 47–50)**: `width += 3` / `height += 3` could integer-overflow for extreme values of `avctx->width/height`, but `ff_set_dimensions` immediately calls `av_image_check_size2` which catches invalid dimensions and resets them to 0 — no path to memory corruption.

2. **`decode_mvc1` pixel writes**: All `ROW16`/`PIX16` macro writes are bounded to `x ∈ [0, width-4]` and `y+row ∈ [0, height-1]` where both `width` and `height` are multiples of 4 (guaranteed by `&= ~3` in init). Frame allocation matches exactly these aligned dimensions.

3. **`decode_mvc2` color table** (`color[128]`): All indexed by `p0 & 0x7F` and `p1 & 0x7F` giving range 0..127 — within bounds.

4. **`decode_mvc2` write positions**: The `(x, y)` tracking is properly bounded. `x` never exceeds `width-4` when writing; `y` is checked against `height` before each new row, preventing writes past end of frame.

5. **All bytestream reads**: Every `bytestream2_get_*u` call is preceded by an explicit `bytestream2_get_bytes_left(gb) < N` guard.

6. **vflip logic**: `dst_start += (height-1)*linesize; linesize = -linesize` correctly inverts the write direction with no under/over-flow of the allocated frame.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
