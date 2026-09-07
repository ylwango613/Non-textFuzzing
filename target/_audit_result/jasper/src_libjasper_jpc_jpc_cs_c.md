After completing all read batches and cross-checking allocator implementations, type sizes, and downstream usage in jpc_dec.c, here is the complete picture:

**Batch 1 (lines 1–500):** `jpc_getms` creates a tmpstream of exactly `ms->len` bytes for each marker, bounding all subsequent reads. `jpc_siz_getparms` uses `jas_alloc2` (overflow-safe mul) for the `siz->comps` array; `numcomps` is validated to `[1, 16384]`.

**Batch 2 (lines 500–1000):** `jpc_cod/coc_getparms`, `jpc_qcd/qcc_getparms` — all array allocations use `jas_alloc2`. `jpc_qcc_getparms` passes a computed `int len` to `jpc_qcx_getcompparms`; when `len` would go negative, the stream read in `jpc_qcx_getcompparms` fails first (EOF on the empty tmpstream), so no unsigned underflow reaches the `len - n` computation.

**Batch 3 (lines 1000–1500):** `jpc_qcx_getcompparms` bounds `numstepsizes` to ≤ 100 (`3*JPC_MAXRLVLS+1`); jas_alloc2 then allocates at most 800 bytes. The `abort()` on NULL is a DoS under OOM, not memory corruption. `jpc_poc_getparms`: `numpchgs = ms->len / 7` (max ≈ 9361) passed to `jas_alloc2`; overflow-safe. `jpc_crg_getparms`: `jas_alloc2(cstate->numcomps, sizeof(jpc_crgcomp_t))` — numcomps ≤ 16384, no overflow. PPM/PPT/COM: all `jas_malloc` calls are bounded by `ms->len` (≤ 65533).

**Batch 4 (lines 1500–1730):** `jpc_unk_getparms`: `jas_alloc2(ms->len, 1)` — bounded. Primitive I/O reads 1–4 bytes with EOF detection.

**Downstream check (jpc_dec.c):** `ccp->stepsizes[bandno]` writes from the parsed compparms into a fixed array of 100 elements; the bounds check in `jpc_qcx_getcompparms` (`numstepsizes > 100` → error) prevents any OOB write there.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
