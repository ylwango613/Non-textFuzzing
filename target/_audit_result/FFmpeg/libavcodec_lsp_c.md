After thorough analysis of the full `lsp.c` file (253 lines), all callers, the header definitions, and related codec files, here are my findings:

**Key analysis performed:**

1. **`ff_cos()` (lines 77–85)**: `ind = arg >> 8` can exceed 63 if `arg > 0x3fff`, reading `tab_cos[64]`/`tab_cos[65]` (array has 65 elements, indices 0–64). `tab_cos[65]` would be an OOB read. However, `tab_cos` is a `static const` array in the read-only data segment; this cannot produce a write primitive.

2. **`lsp2poly` / `lsp2polyf` (lines 110–150)**: Write into `f[i]` up to `f[lp_half_order]`. Arrays callers allocate are `[MAX_LP_HALF_ORDER+1] = [11]`. If `lp_half_order > 10` → OOB stack write. Checked all callers — `LP_ORDER_16k/2 = 10 = MAX_LP_HALF_ORDER` exactly; no caller exceeds this.

3. **`acelp_lsp2lpc` (lines 159–179)**: Stack arrays `f1[MAX_LP_HALF_ORDER+1]` and `f2[MAX_LP_HALF_ORDER+1]`. Called only from `ff_acelp_lp_decode` with `lp_order >> 1 = 5`. Safe.

4. **`ff_amrwb_lsp2lpc` (lines 181–205)**: Stack arrays `buf[MAX_LP_HALF_ORDER+1]` and `pa[MAX_LP_HALF_ORDER+1]`. Called with `LP_ORDER_16k = 20` → `lp_half_order = 10 = MAX_LP_HALF_ORDER` (exactly at boundary, not over). Safe.

5. **`ff_acelp_lp_decode` (lines 207–224)**: Stack array `lsp_1st[MAX_LP_ORDER]`. Only caller (`g729dec.c:490`) passes hardcoded `10`. Safe.

6. **`ff_acelp_lspd2lpc` (lines 226–243)**: Has `av_assert2(lp_half_order <= MAX_LP_HALF_ORDER)`. All callers (wmavoice: 5/8, qcelp: 5, amrnb: 5, sipr16k: 8) are within bounds.

All `lp_order` parameters are codec-internal compile-time constants, not values read from the media bitstream at parse time. No externally controllable size field reaches any allocation or array-index path in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
