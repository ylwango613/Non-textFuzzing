The `adx.c` file itself is only 35 lines and contains a single pure math function (`ff_adx_calculate_coeffs`) with no memory allocation, no external input handling, no buffers, and no pointer arithmetic. The function takes pre-validated `int` parameters and writes exactly two array entries via the caller-provided `coeff[2]` pointer.

There are no `av_malloc`, `memcpy`, `realloc`, packet/chunk size reads, extradata handling, or any of the memory-safety-relevant patterns to audit in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
