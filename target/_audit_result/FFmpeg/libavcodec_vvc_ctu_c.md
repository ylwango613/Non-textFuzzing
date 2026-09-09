`pps_chroma_qp_offset_list_len_minus1 ∈ [0, 5]`, so `c_max ≤ 5` and the loop returns `i ∈ [0, 5]`. `chroma_qp_offset_list[6]` — index 5 is the last valid element. No OOB.

All code paths are properly bounded. The comprehensive analysis of `ctu.c` and its call chains found no externally-triggerable memory-safety vulnerabilities.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
