The file is only 221 lines. I've now read it in full and reviewed the key related structures (`VP9SharedContext`, `VP9BitstreamHeader`, `NVDECContext`) and the VP9 decoder's bitstream parsing code.

**Analysis summary:**

1. **`pixdesc` NULL pointer (lines 39, 76-83):** `av_pix_fmt_desc_get(avctx->sw_pix_fmt)` can return NULL for `AV_PIX_FMT_NONE`, but the NVDEC hwaccel pipeline requires format negotiation to complete before `start_frame` is ever called — so `sw_pix_fmt` will always be a valid VP9-compatible format at this point. Not practically triggerable.

2. **`h->refs[h->h.refidx[i]]` array access (lines 66-68):** `refidx[0..2]` values come from `get_bits(&s->gb, 3)` in `vp9.c:608-612` — exactly 3-bit values (0–7). `refs` is declared as `ProgressFrame refs[8]`. Perfectly bounded; not exploitable.

3. **All loop-indexed array accesses (lines 112-137):** Hardcoded bounds (`i < 2`, `i < 4`, `i < 7`, `i < 3`, `i < 8`) exactly match the fixed-size arrays in both `VP9BitstreamHeader` and `CUVIDVP9PICPARAMS`. No OOB possible.

4. **No `av_malloc`/`memcpy`/`av_realloc` calls** in this file — the file only fills out an on-stack `CUVIDPICPARAMS` struct and delegates to `ff_nvdec_start_frame`. No heap allocation or copy operations to audit.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
