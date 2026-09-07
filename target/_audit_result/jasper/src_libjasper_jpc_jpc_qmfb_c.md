After reading all 3138 lines of `jpc_qmfb.c` in six batches and tracing all callers and related definitions, here is my complete analysis:

**Batch 1 (0–600):** License block, constants (`QMFB_SPLITBUFSIZE=4096`, `QMFB_JOINBUFSIZE=4096`, `JPC_QMFB_COLGRPSIZE=16`), energy weight tables, `jpc_qmfb_split_row`, `jpc_qmfb_split_col`. Buffer checks: stack buffer [4096] used when `bufsize=(numcols+1)/2 ≤ 4096`; at most `m ≤ bufsize` elements written → safe.

**Batch 2 (600–1200):** `jpc_qmfb_join_row`, `jpc_qmfb_join_col`, `jpc_qmfb_join_colgrp`, `jpc_qmfb_join_colres`. Colgrp/colres stack buffers are [65536]. Writes at most `hstartcol * COLGRPSIZE = bufsize * 16 ≤ 4096 * 16 = 65536` → exact fit, safe.

**Batch 3 (1200–1800):** FT forward/inverse lift functions. `jpc_ft_analyze` and `jpc_ft_synthesize`: pass `numcols - maxcols < 16` as `numcols` to colres functions (so maximum written = `4096 * 15 = 61440 < 65536`). Pass full `numcols` to split/join_row (4096-element stack buffer correctly guarded).

**Batch 4 (1800–2400):** NS forward lift colgrp/colres/col functions — same structure, same bounds.

**Batch 5 (2400–3000):** NS inverse lift colgrp/colres/col — same bounds. No unchecked arithmetic.

**Batch 6 (3000–3138):** `jpc_ns_analyze` and `jpc_ns_synthesize` — identical calling pattern to FT variants. `jpc_qmfb_split_col` and `jpc_qmfb_join_col` are defined but **never called** (dead code).

**Checked helpers:** `jas_alloc2`/`jas_alloc3` have overflow-safe multiplication (`jas_safe_size_mul`); on failure they return NULL and code calls `abort()`, not silently under-allocate. No exploitable integer-overflow→malloc path.

**Signed overflow in `JPC_CEILDIVPOW2` for extreme inputs:** only reachable with allocations far beyond JasPer's default 256 MB memory cap; not exploitable.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
