All array accesses are within bounds: `vsad[6]`, `vsse[6]`, `sse[6]`, `pix_abs[2][4]`, `median_sad[6]` — all indices used (max: vsad[5], vsse[5], pix_abs[1][3]) are within the declared sizes. The two wrapper functions null-check `c` before dereferencing. There are no memory allocations, no parsing of untrusted input, and no buffer operations in this file — it is a pure CPU-feature-gated function-pointer initialization routine with no attack surface from crafted media files.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
