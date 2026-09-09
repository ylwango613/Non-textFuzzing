After thorough analysis of `dsp.c` (69 lines) and its full caller context, my findings are:

**`postfilter_c` negative-index analysis:**
- `data[-period-2]` through `data[-period+1]` before the loop: caller passes `buf + 1264`, `period` is clamped to [15, 1022] by `FFMAX(period, CELT_POSTFILTER_MINPERIOD)`. Most negative access: `buf[1264 - 1022 - 2] = buf[240]` — valid within `buf[2048]`.
- Loop writes `data[0]..data[filter_len-1]` = `buf[1264]..buf[1983]` — valid.
- Loop reads `data[i - period + 2]`: for period=1022, most positive is `buf[244]`; for period=15, up to `buf[1970]` — all valid.

**`deemphasis_c` analysis:**
- Reads only `weights[0]`; x86 SIMD reads 4 floats via `movaps`, but `ff_opus_deemph_weights` has ≥12 elements with 16-byte alignment — valid.
- `len` = `frame_size` is validated to be in {120, 240, 480, 960} before this call.

**`ff_opus_dsp_init` analysis:**
- Pure function pointer assignment; no memory operations.

No allocation, no user-controlled sizes passed to malloc, no unbounded memcpy, and all negative-index accesses land within their pre-allocated `float buf[2048]` region.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
