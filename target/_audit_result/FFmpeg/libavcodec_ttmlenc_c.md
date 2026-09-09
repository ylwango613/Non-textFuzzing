I have now completed a thorough analysis of `ttmlenc.c` (393 lines, fully read in one pass) and its call chain including `ass_split.c` and `bprint.c`. Summary of what was checked:

**`ttml_write_header_content`** (lines 293-363):
- `base_extradata_size = 77` (size_t), `av_bprint_init` max is `INT_MAX − 77 = 2147483570`
- `additional_extradata_size` (size_t) assigned from `s->buffer.len` (unsigned int) → max 2147483569
- `av_mallocz(77 + 2147483569)` ≤ `INT_MAX − 1` — no overflow
- `avctx->extradata_size = 12 + additional_extradata_size` ≤ `INT_MAX − 66` — fits in int
- Both `memcpy` calls copy within allocated bounds — no OOB

**`ttml_get_origin` / `ttml_get_extent`** (lines 190-208):
- `av_rescale` uses `int64_t` internally — no overflow hazard
- Division by `play_res_x`/`play_res_y` guarded by `<= 0` check at line 303 before these are ever called

**`ttml_encode_frame`** (lines 79-139):
- Uses `av_bprint_init_for_buffer` (no heap allocation) with `av_bprint_is_complete` check at line 133

**`ass_split.c` — `convert_str`**:
- `len` declared as `int` but assigned from `strcspn()` (`size_t`); could theoretically truncate to negative on 64-bit if a field is > 2 GB, leading to `av_malloc(small)` then `memcpy(..., huge_size_t)` — but requiring a > 2 GB ASS header field makes this impractical as a real attack

**`ff_ass_split_dialog`** has an explicit guard `if (len >= INT_MAX) return NULL`, protecting `convert_str` calls from that path.

**`ff_ass_split_override_codes`**: `text_len` (int) count could theoretically wrap with > 2 GB subtitle text, but is equally impractical.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
