`qsv_api.c` is 43 lines. The single function `av_qsv_alloc_context()` calls `av_mallocz(sizeof(AVQSVContext))` with a compile-time constant — no user-controlled input, no size arithmetic, no buffer operations. `AVQSVContext` itself contains only fixed-size fields. There are no memory safety vulnerabilities in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
