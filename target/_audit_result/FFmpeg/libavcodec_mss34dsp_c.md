The file is only 94 lines. Both functions operate on fixed-size 8×8 blocks with statically bounded indices (0–63), use no dynamic allocation, and perform no arithmetic on attacker-controlled sizes. The callers pass pre-validated `quality` and pre-allocated buffers. There are no reachable memory-safety issues traceable to this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
