The file is only 71 lines — a pure CPU-dispatch init function. The `hf_apply_noise` array is declared `[4]` in the struct; indices 0–3 are assigned, no over-bounds access. There are no allocations, no memcpy calls, no external-input parsing, and no integer arithmetic. No memory-safety issues are present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
