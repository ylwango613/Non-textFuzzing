After a thorough multi-pass read of `vp9dsp_8bpp.c` and its actual implementation in `vp9dsp_template.c` (2578 lines), plus examination of the calling chain in `vp9recon.c`, `vp9.c`, and `vp9_mc_template.c`, I found no exploitable memory-safety vulnerabilities. Key findings:

**Batch 1 (lines 1–600): Intra-prediction functions** — All operate on compile-time-sized blocks (4/8/16/32). The `top[-1]` accesses are intentional (VP9 top-left context), always backed by the decoder's context buffers.

**Batch 2 (lines 600–1110): More intra-prediction macros** — `def_hor_up`, `def_vert_left`, `def_diag_downleft`, etc. all use `pixel v[size-1]` or `v[size*2-2]` stack arrays. Array index arithmetic is tight but correct: at boundary iterations, memcpy/memset_bpc lengths become 0 (harmless OOB pointer dereference of `v+size-1` that is never dereferenced).

**Batch 3 (lines 1155–1752): Inverse transform wrappers** — `tmp[sz*sz]` and `out[sz]` are all compile-time constants (sz ∈ {4,8,16,32}). For 8bpp (`dctint = int`), all intermediate multiplications (max ~562M) stay within `int32_t` range.

**Batch 4 (lines 1780–2024): Loop-filter and copy/avg functions** — Fixed kernel sizes; all pixel reads/writes use bounded strides from the frame buffers.

**Batch 5 (lines 2026–2578): Motion-compensation functions** — The critical stack buffers:
- `do_8tap_2d_c`: `pixel tmp[64*71]`; `tmp_h = h+7`. For max VP9 h=64: `tmp_h=71` ≤ 71 ✓
- `do_scaled_8tap_c`: `pixel tmp[64*135]`; `tmp_h = (((h-1)*dy+my)>>4)+8`. VP9 check at `vp9.c:867` enforces `refw ≤ 2*w`, giving `dy ≤ 32`. For h=64, dy=32, my=15: `tmp_h=134` ≤ 135 ✓
- `do_scaled_bilin_c`: `pixel tmp[64*129]`; same dy bound → `tmp_h=128` ≤ 129 ✓

All buffer sizes are correctly dimensioned for VP9 specification constraints enforced at decode time.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
