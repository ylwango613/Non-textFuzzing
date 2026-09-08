I have now fully read and analyzed every function in the 348-line file. Let me summarize the key findings from each section:

**Group 1 (lines 1-145):** `import_palette`, `bitplanar2chunky`, `bitline2chunky`, `chunky2chunky`, `import_format` — data-flow analysis:
- `import_palette` writes `palette_size/2` or `palette_size/3` uint32_t entries. Destination bounds depend on caller.
- Bit reader loops consume exactly `bpp * height * aligned_width` bits.

**Group 2 (lines 147-245):** HAM decode functions — `cdxl_decode_ham6` has `new_palette[16]`, `cdxl_decode_ham8` has `new_palette[64]`. Both call `import_palette`. For HAM paths to execute: line 295 enforces `palette_size == (1 << (bpp-1))`. For bpp=6: palette_size must be exactly 32 → type==1 gives 32/2=16 entries (fits [16]), type==0 gives 32/3=10 entries (fits [16]). For bpp=8: palette_size must be exactly 128 → type==1 gives 128/2=64 (fits [64]), type==0 gives 128/3=42 (fits [64]). **No overflow.**

**Group 3 (lines 247-327):** `cdxl_decode_frame` — key arithmetic:
- `c->video_size = buf_size - c->palette_size - 32`: guarded by line 273 check.
- `h * w` in `av_fast_padded_malloc` (line 311-312): both `h`, `w` ≤ 65535 (AV_RB16). Max product = 65535² = 4,294,836,225 → overflows int32 to −131,071. Adding 64 → −131,007. Passed as `size_t` this becomes ~18.4 EB on 64-bit or ~4 GB on 32-bit — malloc fails → ENOMEM caught at line 313. **Cannot produce underallocation.**
- Video size check at line 290 uses `(int64_t)c->bpp` to prevent overflow and exactly computes total bits required, preventing OOB read even with `UNCHECKED_BITSTREAM_READER`.
- PAL8 palette path: `frame->data[1]` = 1024 bytes = 256 uint32_t. type==1 max 512/2=256, type==0 max 768/3=256. Exactly fits.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
