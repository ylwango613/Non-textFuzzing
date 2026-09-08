**Batch 1 (lines 1–450):** Tables, VLC init, `mobiclip_init()`, `setup_qtables()`, `idct()`, beginning of `add_coefficients()`. No OOB yet — qtab/pre arrays properly sized, `av_calloc` uses validated width.

**Batch 2 (lines 449–899):** Rest of `add_coefficients()`, intra prediction helpers, `predict_intra()` cases 0-3. The `pos >= size*size` guard before every `qtab[pos]` / `mat[ztab[pos]]` access is present. `arr1[16]`/`arr2[16]` are exactly the right size for the maximum size=16 call.

**Batch 3 (lines 899–1207):** `predict_intra()` cases 4-8, `process_block()`, `decode_macroblock()`, `predict_motion()`. Motion-vector boundary checks cover all four half-pixel cases (methods 0-3). `run_residue` indices are computed as 0-127 or 128-223 — both within the [2][256] array.

**Batch 4 (lines 1209–1355):** `mobiclip_decode()`. P-frame `motion[]` accesses: max index `width/16+2`, allocated `width/16+3` — just barely in bounds. `get_prediction()` writes to `pre[index+4..+9]`, max index 24 < 32.

**Key findings after all four passes:**

- `add_coefficients()` — bounds-checked before every `qtab`/`ztab` access.
- `predict_motion()` — all four half-pixel copy cases correctly bounded.
- `get_prediction()` — `s->pre[0..24]` accesses within the 32-byte field.
- `setup_qtables()` — quantizer clamped 12–161 before indexing quant tables.
- `run_residue` — indices provably 0–223, within [2][256].
- `mobiclip_init()` — `av_calloc` with width already verified multiple-of-16.
- No unchecked `av_malloc` multiplications, no fixed stack buffers written from stream data.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
