The file is only 59 lines with a single function. I've now fully traced all callers and their downstream usage. The function does only integer arithmetic — no allocation, no array indexing, no pointer ops. Callers all guard the return value:
- `wma.c`: pre-filters `sample_rate > 50000`, calls with `decode_flags=0` → no adjustment, result ∈ [9,11]
- `wmaprodec.c`: explicitly checks `bits > WMAPRO_BLOCK_MAX_BITS(13)` and returns error
- `wmalosslessdec.c`: `av_assert0(samples_per_frame <= WMALL_BLOCK_MAX_SIZE)` where `WMALL_BLOCK_MAX_SIZE = 1<<14`; the maximum possible return value is 14, so `1<<14 = 16384 ≤ 16384` — the assert never fires at maximum input

No memory safety issues exist in `wma_common.c` or its direct call chain.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
