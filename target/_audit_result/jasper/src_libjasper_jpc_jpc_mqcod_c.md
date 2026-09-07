`jpc_mqcod.c` contains only one construct: a 94-element static global array `jpc_mqstates[47 * 2]` initialized entirely with compile-time constant values (hardcoded hex literals and pointers to fixed elements of the same array). The highest index referenced in the initializer is `[93]`, which is within the array's bounds. There are no functions, no dynamic allocation, no loops, no user-controlled data paths, and no pointer arithmetic involving file-derived values anywhere in the file or its header.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
