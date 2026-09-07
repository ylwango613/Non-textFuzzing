After reading all 308 lines of `jpc_mqdec.c` in two batches and tracing every context-sensitive call into `jpc_mqdec.h`, `jpc_mqcod.h`, `jpc_t1cod.h`, and `jpc_t1dec.c`, my findings are:

- **No malloc with file-controlled size**: `jpc_mqdec_create` calls `jas_alloc2(maxctxs, sizeof(jpc_mqstate_t *))` where `maxctxs = JPC_NUMCTXS` (compile-time constant = 19).
- **No array index from file**: `jpc_mqdec_setcurctx` uses context numbers from `jpc_zcctxnolut`/`jpc_scctxnolut`/`jpc_magctxnolut` (statically initialized LUTs bounded to valid context indices), and from compile-time constants `JPC_AGGCTXNO`, `JPC_UCTXNO`.
- **`jpc_mqdec_setctxs` loop bounds**: correctly guarded by `JAS_MIN(maxctxs, numctxs)`, writes only within the allocated `ctxs` buffer.
- **Byte-stream arithmetic only**: `jpc_mqdec_bytein` and the `jpc_mqdec_bytein2`/`jpc_mqdec_renormd` macros read single bytes via `jas_stream_getc()` and apply fixed-width shifts/additions to `uint_fast32_t` registers — no memory dereference with attacker-influenced offsets.
- **`jpc_mqstates[]` access**: `jpc_mqdec_setctxs` uses `&jpc_mqstates[2 * ctxs->ind + ctxs->mps]` where `ctxs` is always `jpc_mqctxs` (static, with `ind` ≤ 46, well within the `jpc_mqstates[94]` array).
- **`jpc_mqdec_setctx`**: defined but never called in the production codebase (dead code).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
