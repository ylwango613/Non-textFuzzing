The file `libavcodec/riscv/cpu_common.c` is a single-line stub that includes `libavutil/riscv/cpu_common.c`. The actual implementation contains only:

1. A conditional global variable declaration `ff_rv_zbb_supported = 0` guarded by `#ifndef __riscv_zbb`.
2. An ELF constructor `probe_zbb()` that calls `av_get_cpu_flags()` and masks with `AV_CPU_FLAG_RVB_BASIC`, storing the boolean result into the global variable.

There are no memory allocations, no buffer operations, no array indexing, no external data parsing, and no user-controlled inputs in this file or its included implementation. The constructor only reads CPU feature flags (a kernel/hardware interface) and writes a single byte. There is no attack surface reachable from a crafted media file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
