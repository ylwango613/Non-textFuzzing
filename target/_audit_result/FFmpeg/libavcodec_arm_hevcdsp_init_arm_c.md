The file is 35 lines of pure CPU-dispatch initialization with no memory allocation, buffer access, array indexing, or handling of external input. The function simply detects NEON availability and delegates to `ff_hevc_dsp_init_neon()`. No untrusted data is processed here.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
