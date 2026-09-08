This file is a **build-time host tool** only — it generates hardcoded lookup tables that get embedded into the FFmpeg binary. There is no runtime execution path from any media-file parser to this code, and it processes no external input whatsoever. All array sizes (`TMP_LUT_SIZE = 4096`, `LUT_SIZE = 8192`) are compile-time constants, and every loop index is bounded by those constants before any array write.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
