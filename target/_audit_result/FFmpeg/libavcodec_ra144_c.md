**Analysis Summary:**

**Group 1 (Lines 1–1505): Constant table data**
- `ff_gain_val_tab[256][3]`, `ff_gain_exp_tab[256]`, `ff_cb1_vects[128][40]`, `ff_cb2_vects[128][40]`, `ff_cb1_base[128]`, `ff_cb2_base[128]`, LPC codebooks — all purely static constant data, no runtime logic here.

**Group 2 (Lines 1507–1724): Runtime functions**

Key functions and their safety analysis:

**`ff_copy_and_dup()` (lines 1530–1537):** `offset` comes from `cba_idx` after `+= 19`, range 20..146. `source = adapt_cb + (146 - offset)` → range `[0..126]`. Both memcpy calls stay within `adapt_cb[148]`. Safe.

**`add_wav()` (lines 1507–1524):** `n = gain` from `get_bits(gb, 8)` → 0..255. Tables `ff_gain_val_tab[256]` and `ff_gain_exp_tab[256]` exactly fit. Safe.

**`ff_subblock_synthesis()` (lines 1694–1724):** Indices from bitstream:
- `cb1_idx` — 7 bits → 0..127; table `ff_cb1_vects[128]` and `ff_cb1_base[128]`. Safe.
- `cb2_idx` — 7 bits → 0..127; table `ff_cb2_vects[128]` and `ff_cb2_base[128]`. Safe.
- `cba_idx` — 7 bits → 0..127; after `+= 19` becomes 20..146 passed to `ff_copy_and_dup`. Safe.

**LPC codebook access (ra144dec.c line 96):**
```c
lpc_refl[i] = ff_lpc_refl_cb[i][get_bits(&gb, sizes[i])];
```
`sizes[] = {6,5,5,4,4,3,3,3,3,2}` exactly match the codebook sizes (64,32,32,16,16,8,8,8,8,4). Safe.

**`ff_eval_refl()` / `ff_eval_coefs()`:** Operate on stack arrays of exactly `LPC_ORDER=10` with correct loop bounds `i` and `j`. No OOB.

**Conclusion:** All index values from the bitstream are gated by their exact bit-width to match their respective table sizes. The `adapt_cb[148]` over-allocation (+2 guard entries) is sufficient. No integer overflow/underflow, no OOB read/write, no heap under-allocation paths are reachable from crafted input.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
