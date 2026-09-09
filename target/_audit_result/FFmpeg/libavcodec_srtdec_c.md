After fully reading `srtdec.c` (116 lines) and all directly-called functions (`htmlsubtitles.c`, `ass.c`), I've verified each memory operation in the call chain:

- **`scantag()`** (htmlsubtitles.c:102): `char buffer[128]`, loop `len = 0..127`, max index written is 127. No OOB write.
- **`face=` attribute copy** (htmlsubtitles.c:274): `strcspn` result is bounded by the tag content (max 127 chars from `scantag`), so `len+1 ≤ 128`. `FFMIN(sizeof(face)=128, 128)=128`. `av_strlcpy(face, param, 128)` copies at most 127 chars + null. Safe.
- **font tag stack** (htmlsubtitles.c:159): `stack[16]`, push guarded by `sptr < FF_ARRAY_ELEMS(stack)-1 = 15`, pop by `sptr > 0`. All accesses in-bounds.
- **`param[-1]`** (htmlsubtitles.c:273): `param` always points at least 5 bytes past the buffer start when the `face=` branch is reached. In-bounds.
- **side-data read** (srtdec.c:68–72): `size == 16` exact check before 4×`AV_RL32` reads. Safe.
- **`ff_ass_add_rect2`** (ass.c:119): `num_rects >= UINT_MAX` guard prevents overflow; `av_realloc_array` with two separate factors is safe.
- **`readorder++`** (srtdec.c:82): signed overflow of `int` field — not a memory safety issue, just wrong numbering.
- **`av_bprintf` calls**: all use `AV_BPRINT_SIZE_UNLIMITED` — no overflow possible.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
