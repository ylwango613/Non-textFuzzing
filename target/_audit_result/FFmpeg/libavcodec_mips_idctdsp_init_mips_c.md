The file is 64 lines — a pure CPU-capability dispatcher that assigns MIPS-optimized function pointers into `IDCTDSPContext`. There are no memory allocations, no array indexing, no arithmetic, no external data reads, and no buffer operations of any kind. The function pointer targets (`ff_simple_idct_put_8_mmi`, etc.) are compile-time constants. No untrusted data touches this code path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
