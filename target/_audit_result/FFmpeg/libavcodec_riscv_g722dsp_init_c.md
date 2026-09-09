After reviewing the complete call chain — `g722dsp_init.c`, `g722dsp_rvv.S`, `g722dsp.h`, `g722.h`, `g722dec.c`, `g722enc.c`, and the ARM equivalent — here is my finding:

- `g722dsp_init_riscv` merely assigns the RVV function pointer; no memory operations occur there.
- `ff_g722_apply_qmf_rvv` (RVV assembly) loads exactly 24 `int16_t` from `prev_samples` and writes exactly 2 `int32_t` to `xout` — matching the reference C implementation.
- The callers initialise `prev_samples_pos = 22`, increment it by exactly 2 per iteration (always keeping it even), and call `apply_qmf(prev_samples + pos - 24, xout)` before the wrap-around check. The worst-case pointer offset is `prev_samples + 1000`, reading indices [1000..1023], all within the 1024-element `prev_samples` buffer.
- No attacker-controlled size fields, no heap allocations, no integer-overflow-to-underalloc paths exist in this file or its direct call chain.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
