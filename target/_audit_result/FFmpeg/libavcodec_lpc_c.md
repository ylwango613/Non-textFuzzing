After reading the entire `lpc.c` (371 lines, all batches), the header `lpc.h`, and tracing all callers via grep, here is my analysis:

**Batch 1 (lines 1–207):** `compute_ref_coefs` uses fixed-size stack arrays `gen0[MAX_LPC_ORDER]`, `gen1[MAX_LPC_ORDER]` (32 doubles each). A `max_order > 32` would produce a stack overflow. `ff_lpc_calc_ref_coefs` passes its `order` arg here without bounds-checking.

**Batch 2 (lines 208–371):** `ff_lpc_calc_coefs` guards `max_order ≤ MAX_LPC_ORDER` only with `av_assert2` (compiled out in release builds). `ff_lpc_init` allocation: `(blocksize + 2 + FFALIGN(max_order, 4)) * sizeof(double)` — integer addition is in 32-bit `int` before the `size_t` multiply, so wrapping is possible at extreme values.

**Caller analysis:**
- All callers of `ff_lpc_calc_coefs` are **encoders** (flacenc, alacenc, mlpenc, ra144enc) with internally-set `blocksize`/`max_order`.
- `ff_lpc_calc_ref_coefs` is called only from `cngenc.c` with hardcoded `order = 10`.
- `ff_lpc_calc_ref_coefs_f` is called only from `aacenc_tns.c` with `ord_g ≤ 12` (bounded by `TNS_MAX_ORDER = 20 < MAX_LPC_ORDER = 32`).
- `ra144dec.c` includes `lpc.h` but does **not** call `ff_lpc_calc_*` functions; it uses its own LPC tables directly.

**Conclusion:** All LPC utility functions in `lpc.c` are used exclusively by **encoders**, never by decoders parsing attacker-controlled bitstream data. Every potentially dangerous parameter (`max_order`, `blocksize`, `order`) is either a compile-time constant, hardcoded in the calling codec, or bounded before reaching lpc.c. None of the potential issues (stack overflow in `compute_ref_coefs`, integer overflow in `ff_lpc_init`) is reachable from a crafted media file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
