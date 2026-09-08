Now I have all the context needed. Let me analyze the complete picture:

**`g722dsp.c` analysis:**
- `g722_apply_qmf()` (lines 29–66): performs a pure QMF computation accessing exactly 24 `int16_t` elements from `prev_samples` (12 pairs via `*prev_samples++`) and writing exactly 2 elements to `xout[2]`. No dynamic allocation, no loops, no variable-length access — completely hardcoded access pattern.
- `ff_g722dsp_init()` (lines 68–79): simply assigns a function pointer.

**Caller analysis (g722dec.c, g722enc.c):**
- `c->prev_samples` is a fixed array of `PREV_SAMPLES_BUF_SIZE = 1024` elements.
- `prev_samples_pos` is initialized to 22 and only resets to 22 when `>= 1024`.
- At every call site: two samples are written first (pos becomes ≥ 24), then `apply_qmf(prev_samples + pos - 24, ...)` is invoked, ensuring the pointer is always at index ≥ 0 and the 24-element read window never exceeds index 1023.
- The underflow path (`pos < 24`) is structurally impossible: initialization sets pos = 22, each iteration adds 2, and the reset path sets pos = 22 (not 0).

**Result:** `g722dsp.c` is a 80-line pure-math DSP file with no dynamic allocation, no file parsing, no variable-length memory access, and no externally-controlled sizing. The fixed 24-element QMF window is always satisfied by callers. No memory safety vulnerabilities are present in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
