**Analysis summary:**

The file (`idctdsp_msa.c`) is 147 lines containing three MIPS MSA SIMD implementations of DCT block pixel scatter functions and their public wrappers.

**What I examined:**

1. **`LD_SH8(block, 8, ...)`** — loads 8×16-byte vectors (128 bytes total) from `block`. The `block` is always a fixed 8×8 int16_t DCT block (exactly 128 bytes) allocated internally by the codec. No external size control.

2. **`LD_UB8(pixels, stride, ...)`** in `add_pixels_clamped_msa` — loads 16 bytes per row (v16u8 = 128-bit MSA vector) but only uses the lower 8 bytes via `ILVR_B4_UH`. The upper 8 bytes are read and discarded. While this reads 8 bytes beyond the intended 8-pixel row width, FFmpeg allocates AVFrame buffers with `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) of extra padding at the end — the worst-case out-of-bounds read (`pixels + 7*stride + 15`) is well within that padding. Not exploitable.

3. **`SD4` stores** — write exactly 8 bytes (uint64_t) per row, matching the 8-pixel block width. No overflow.

4. **`ptrdiff_t → int32_t` truncation** in the public wrapper calling the static function — stride is always a small positive integer in practice; not controllable by a media file attacker to a dangerous value.

5. **No dynamic allocation, no parsing of external container fields, no integer overflow leading to underallocation, no memcpy with attacker-controlled sizes** — the entire file operates on fixed-size, internally-managed DCT blocks and AVFrame buffers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
