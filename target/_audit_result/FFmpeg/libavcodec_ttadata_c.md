**Summary of analysis:**

**`ff_tta_shift_1[]`** — 41 elements (indices 0–40); `ff_tta_shift_16 = ff_tta_shift_1 + 4`, valid offset indices 0–36.

**`ff_tta_filter_init` shift-1 indexing (line 54):** If `shift=0`, reads `ff_tta_shift_1[-1]` — OOB. However, all callers (`tta.c:262`, `ttaenc.c:104`) pass only `ff_tta_filter_configs[bps-1]`, whose values are `{10,9,10,12}`. The `bps` value is validated by a switch/case before reaching that call, so shift is always 9, 10, or 12. No externally-controllable path exists.

**Rice k0/k1 growth and `ff_tta_shift_16[k+1]` access:** k0/k1 start at 10, increment by 1 per sample. At k=35, the increment condition reads `ff_tta_shift_16[36]` = `ff_tta_shift_1[40]` = `0xFFFFFFFF` (last valid element). Since `sum` is `uint32_t`, `sum > 0xFFFFFFFF` is always false — k never reaches 36, so `ff_tta_shift_16[37]` (OOB) is never read.

**`allocate_buffers`:** `frame_length` is bounded to ~8.76 M (sample\_rate ≤ 0x7FFFFFu), channels to 1–16, and `av_calloc` internally checks for multiplication overflow. The overflow guard at tta.c:215 is redundant but not bypassed.

**Decode loop bounds:** `decode_buffer + (framelen * s->channels)` — both factors are validated, product fits in `int32_t` and matches the allocation. `ch_ctx` accesses are bounded to `[0, channels-1]`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
