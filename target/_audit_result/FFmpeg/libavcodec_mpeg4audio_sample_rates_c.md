The `.c` file is a pure data file — 13 sample-rate constants in a 16-element array. All callers read a 4-bit bitstream field (values 0–15, always within array bounds), and the primary consumer `get_sample_rate()` specially handles value 0x0f=15 (escape) without touching the table, so no OOB is possible. All other call sites iterate with explicit loop bounds. There are no memory allocations, no pointer arithmetic, and no externally-controlled size computation in this file or its direct data consumers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
