Based on the complete read of `pgx_dec.c` and all relevant supporting code, let me summarize the analysis groups:

**Group 1 — Header parsing (`pgx_gethdr`, `pgx_getuint32`):**  
`pgx_getuint32` accumulates digits with `v = 10 * v + c - '0'` without overflow check. However, downstream mitigations handle all overflow scenarios: `jas_safe_size_mul` catches width×height overflow, `jas_matrix_create` checks `numcols < 0`, and `jas_image_cmpt_create` checks `width < 0 || height < 0`. No exploitable path.

**Group 2 — `pgx_getword` (lines 352–379):**  
- `prec > 32` check allows prec=32 through, then `val &= (1 << 32) - 1` is C UB (shift of int by its width). On x86/GCC this typically produces `val &= 0`, zeroing the value — wrong data, not memory corruption.  
- Signed left shift UB: `(c & 0xff) << (8 * j)` when j=3 and c≥0x80 sets the sign bit — UB, but OR into `uint_fast32_t` + subsequent masking prevents OOB writes.

**Group 3 — `pgx_wordtoint` (lines 513–519):**  
`1 << prec` and `1 << (prec-1)` are UB for prec=32; `1 << (prec-1)` is UB for prec=0. These produce wrong pixel data but do not corrupt memory.

**Group 4 — `pgx_getdata` allocation and index (lines 315–350):**  
`jas_matrix_create(1, hdr->width)` allocates exactly `hdr->width` elements; the inner loop uses `x` from 0 to `hdr->width - 1` — perfect bounds. All allocation returns are checked. `jas_safe_size_mul` guards the num_samples check. `max_samples` (64 MB) ensures total allocation is bounded.

**Group 5 — `jas_image_addcmpt`/`jas_image_cmpt_create` with file-controlled `prec`:**  
`cmptparm.prec = hdr.prec` where hdr.prec is `uint_fast32_t`. The parameter `depth` in `jas_image_cmpt_create` is `uint_fast16_t`, and `jas_safe_intfast32_mul3(width, height, depth, 0)` guards the cps_ computation. Large/wrapped prec causes allocation failure, not exploitation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
