After thorough analysis of `celp_math.c` (122 lines) and its call graph:

- **`ff_exp2`**: Both array accesses are safe. `exp2a[power>>10]` — with `power` a `uint16_t` masked to ≤`0x7fff` by the `av_assert2`, `power>>10` ≤ 31, within `exp2a[32]`. `exp2b[(power>>5)&31]` — `&31` hard-caps the index to 31, within `exp2b[32]`.
- **`ff_log2_q15`**: After the normalization shift, `frac_x0 = (value & 0x7c000000) >> 26` extracts bits 26–30, yielding 0–31. Accesses `tab_log2[frac_x0]` and `tab_log2[frac_x0+1]` (indices 0–32) against a 33-element table. Safe.
- **`ff_dot_product`**: No internal bounds checking, but every caller passes compile-time constants (`LPC_FRAME`, `SUBFRAME_LEN`, `PITCH_ORDER`, `HALF_FRAME_LEN`) as `length`. No externally-controlled size reaches this function.
- **`bidir_sal`** (inline in header): The `value >> -offset` branch would be UB if `offset == INT_MIN`, but callers derive `offset` from bounded arithmetic (`(mr_energy >> 15) - 25`, `14 - av_log2(...)`) that cannot reach `INT_MIN` in practice.
- **`ff_celp_math_init`**: Only sets a function pointer. No memory operations.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
