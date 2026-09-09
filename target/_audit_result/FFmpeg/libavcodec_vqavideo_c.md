Reading the file in batches. Starting with lines 1–300 (init + decode_format80).

**Batch 1 findings (lines 1–300):**
- `vqa_decode_init`: `ff_set_dimensions` enforces `max_pixels = 307200` (640×480 default); if it fails, `s->width = s->height = 0` and we return early. `decode_buffer_size = (width/4)*(height/vh)*2` ≤ 76800 — no overflow possible.
- `decode_format80`: Two guard macros: `CHECK_COUNT()` verifies `dest_index + count ≤ dest_size`; `CHECK_COPY(idx)` verifies `idx ≥ 0 && idx + count ≤ dest_size`. Both operands fit well within int range given the max_pixels constraint.

Now reading lines 300–600 (chunk scanning + PAL8 rendering).

**Batch 2 findings (lines 300–600):**
- CPL0 palette: `chunk_size / 3 > 256` check prevents more than 256 iterations; `s->palette[255]` is the last valid slot.
- CBF0 full codebook: explicit `chunk_size > MAX_CODEBOOK_SIZE` guard before `bytestream2_get_buffer`.
- CBFZ codebook: routed through `decode_format80` with `dest_size = codebook_size`; CHECK_COUNT/CHECK_COPY guard all writes.
- PAL8 vector rendering: For v2, `lobytes` and `hibytes` are bounded by `decode_buffer_size`; for v1, `lobytes*2+1 ≤ decode_buffer_size - 1`. `vector_index` max = 65535 << 4 = 1,048,560; highest access is byte 1,048,575, well within `codebook_size = 2,097,152`.
- CBP0 partial accumulation: `chunk_size > MAX_CODEBOOK_SIZE - next_codebook_buffer_index` check (correctly evaluated in unsigned arithmetic) prevents exceeding the 2,097,152-byte buffer.

Now reading lines 600–861 (CBPZ + hicolor decoder + frame decode).

**Batch 3 findings (lines 600–861):**
- CBPZ accumulation: same size guard as CBP0; after countdown triggers, `decode_format80` is called on `next_codebook_buffer` with `dest_size = codebook_size`; macros still protect every write.
- `vqa_decode_frame_hicolor`: `vector_index` checked with `if (vector_index >= MAX_VECTORS) return AVERROR_INVALIDDATA` before the `memcpy(dst, src, ...)`. For all type categories, vector_index ≤ 8191 << anything still falls far below 65536. Max src offset = 8191 × 32 = 262,112; codebook has 2,097,152 bytes.
- Hicolor `dst` pointer: `y_pos * linesize[0] + 2 * x_pos`; both y_pos and x_pos are bounded by dimensions from `ff_set_dimensions`, frame was allocated to those dimensions — no OOB.
- `chunk_size + (chunk_size & 0x01)` can wrap to 0 on `unsigned` overflow when `chunk_size = UINT_MAX`; `bytestream2_skip` clips internally so the position just stays put — parsing confusion, not a memory corruption.
- `decode_format80` called with `chunk_size` cast from `unsigned int` to `int`: if > INT_MAX, it becomes negative and the `src_size < 0` guard rejects it.

**Aggregated assessment:**

After exhaustive multi-batch review of all 861 lines, every memory-touching operation (codebook writes via `decode_format80`, partial codebook accumulation, frame buffer writes, palette writes) is guarded by explicit bounds checks that correctly prevent out-of-bounds access given the `max_pixels = 307200` constraint enforced at init time.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
