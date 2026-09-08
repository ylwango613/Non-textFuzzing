After thorough analysis of the complete file and its calling context:

**Analysis summary:**
- `hevcdsp_init_aarch64.c` is a pure DSP initialization file — it assigns NEON/i8mm assembly function pointers into `HEVCDSPContext`
- All macro-generated array indices (1–9 for first dim, 0–1 for v/h dims) are compile-time constants that fit within the declared `[10][2][2]` bounds
- There are no `malloc`/`av_malloc`, no `memcpy`, no parsing of external/untrusted data
- The `hevc_dequant_*_neon` wrappers dispatch on `log2_size` with `av_unreachable` as the default — not a memory corruption path even if the default is reached
- `ff_hevc_dsp_init_aarch64` only runs at codec init time, not per-frame, and uses no runtime-computed indices

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
