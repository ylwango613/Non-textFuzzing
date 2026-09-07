Batch 1 (lines 1–500): License/includes, `jas_cmprof_createfromclrspc`, `jas_cmprof_createsycc`, `jas_cmprof_createfromiccprof`, `jas_cmprof_create/destroy/copy`, `jas_cmxform_create`, and beginning of `jas_cmxform_apply`. Key observations:
- `jas_cmxform_apply` declares `jas_cmreal_t buf[2][APPLYBUFSIZ]` (2×2048 doubles) on the stack; bufmax = 2048/maxchans controls how many pixels per pass.
- No direct malloc calls in jas_cm.c that don't go through jas_alloc2/jas_realloc2.

Batch 2 (lines 500–999): Remainder of `jas_cmxform_apply`, pxformseq CRUD, shapmat apply (mono/triclr), `jas_cmshapmatlut_set`, `jas_cmshapmatlut_lookup`, `jas_cmshapmatlut_invert`. Key observations:
- `jas_cmshapmatlut_set`: `lut->size = curv->numents` (int ← uint32). If > INT_MAX, lut->size wraps negative; `jas_alloc2` receives huge size_t → overflow guard fires → NULL → error path. Safe.
- `jas_cmshapmatlut_lookup`: bounds via `lo < 0` and `hi >= lut->size` checks; since `lo ≤ hi` always, passing the `hi` check implies `lo` is also in range. Safe.
- Buffer sizing in `jas_cmxform_apply`: `m = bufmax = APPLYBUFSIZ/maxchans`; max index written per channel i is `i + (m-1)*nchans ≤ bufmax*maxchans - 1 ≤ 2047`. Safe.

Batch 3 (lines 999–1290): `jas_cmshapmatlut_invert`, matrix inversion, `icctoclrspc`, `mono`, `triclr`, `jas_cmgetint/putint`, `jas_clrspc_numchans`. Key observations:
- `jas_cmshapmatlut_invert(invlut, lut, n=lut.size)`: `assert(n>=2)` guards against n<2; allocation via `jas_alloc2(n, sizeof(double))` with overflow check; writes exactly n elements. Safe.
- `mono`/`triclr` reference-counting logic: `jas_cmpxform_copy` increments refcnt before `jas_cmpxform_destroy` decrements it; object stays alive. No UAF/double-free.
- `jas_cmgetint`/`jas_cmputint`: `1 << prec` UB if prec ≥ 31, but these do not affect buffer addressing.
- `total = width * height` overflow: if wraps to negative/small value the loop runs fewer iterations, no OOB on fmt->buf.

`jas_alloc2`/`jas_realloc2` confirmed to call `jas_safe_size_mul` with overflow detection — all allocation sites in jas_cm.c are covered.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
