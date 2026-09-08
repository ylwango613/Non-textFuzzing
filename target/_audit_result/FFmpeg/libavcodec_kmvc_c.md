Full analysis complete. The file is 412 lines and I've read it entirely. Let me summarize my findings for each attack surface:

**BLK macro (line 59):** `data[av_clip((x)+(y)*320, 0, 320*200-1)]` — all frame buffer accesses are hard-clamped; no OOB possible through this macro.

**bytestream2 reads:** Lines 71-77 of bytestream.h confirm `bytestream2_get_*` returns 0 when the buffer is exhausted — no OOB reads from packet data.

**Palette bounds (decode_init, lines 381-386):** `palsize = AV_RL16(extradata+10)` is validated `< MAX_PALSIZE (256)`. In `decode_frame` the loop `for (i=1; i<=ctx->palsize; i++)` writes to `ctx->pal[1..255]` at most — within the 256-element array.

**Palette special-case (decode_frame, lines 283-288):** `ctx->pal[i + (header & 0x81)]` where `header & 0x81` ∈ {0,1,128,129} and `i < 127`, so the maximum index is `126 + 129 = 255` — within bounds.

**Dimension check (decode_init, lines 364-367):** `width > 320 || height > 200` → error. The `frm0/frm1` buffers are exactly `320×200` and all decode loops are bounded by these checked values.

**extradata palette load (lines 389-396):** Only entered when `extradata_size == 1036`; reads `12 + 256×4 = 1036` bytes — exactly the buffer size.

**MV validation:** Both intra (line 110) and inter (line 210) check the computed linear offset against the buffer bounds before using it, and BLK clips anyway.

**Output copy (lines 337-341):** `memcpy(out, src, avctx->width)` with `width ≤ 320` and `height ≤ 200`; `src` traverses `frm0/frm1` at stride 320 — no OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
