The file `wma_freqs.c` is 29 lines long and contains only a single compile-time constant array definition. I've verified the callers in `wma.c` (loops bounded to i < 25) and `binkaudio.c` (num_bands capped at 25, `bands[26]` has sufficient capacity). No dynamic allocation, no external input processing, no pointer arithmetic.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
