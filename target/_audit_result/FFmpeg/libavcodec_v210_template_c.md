**Complete analysis of v210_template.c:**

The file is 81 lines. Key findings per path:

**Buffer allocation vs. writes:** `encode_frame()` allocates `height × stride` bytes, where `stride = ((width+47)/48)*48 × 8/3`. The template independently recomputes the same `stride` and `line_padding`. I traced through all partial-pixel cases (width = 2, 4, 6, 8, 10, 24, 26, 48) and confirmed that bytes-written-per-row always equals `stride` exactly — no OOB write to `dst`.

**AVX512ICL sample_factor=4 path:** `sample_size = 24`, `dst += sample_w × 16 × 4`. Pack_line for 24 pixels = 4 WRITE_PIXELS groups × 4 × 4 bytes = 64 bytes = `sample_w × 64`. The advance matches the write, no gap and no overrun.

**`line_padding` sign:** `stride` is `aligned_width × 8/3` (multiple of 48, exact), always ≥ the data bytes formula. Never negative; `memset(dst, 0, line_padding)` is always safe.

**Source-array reads (y/u/v):** Frame buffers are allocated by FFmpeg's frame allocator with `linesize ≥ width × BYTES_PER_PIXEL`. The stride-advance at end of each row (`y += linesize/BPP - width`) is correct. All pixel accesses stay in bounds.

**Encoder vs. decoder scope:** `v210_template.c` is encoder-side only. Attackers trigger decoders (v210dec.c) via crafted media files; the encoder is driven by application-controlled frames, not raw bitstream bytes. v210dec.c has its own size checks and does not include this template.

**`avctx->height × stride` int multiplication** in encode_frame line 78 could overflow for extreme dimensions, but: (a) it's in v210enc.c, not v210_template.c; (b) FFmpeg enforces global dimension limits upstream of codec init; (c) encode_init already rejects odd widths.

No memory-safety bug reachable from crafted media found in v210_template.c or its direct supporting code.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
