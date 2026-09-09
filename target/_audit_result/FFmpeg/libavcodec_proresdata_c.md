`proresdata.c` is a 54-line pure data file containing five statically-initialized constant arrays (`ff_prores_progressive_scan[64]`, `ff_prores_interlaced_scan[64]`, `ff_prores_dc_codebook[7]`, `ff_prores_run_to_cb[16]`, `ff_prores_level_to_cb[10]`). It contains no executable code, no functions, no dynamic memory allocation, no loops, no conditionals, and no external input handling. All arrays are fixed-size compile-time constants with correct element counts matching their declarations in the header.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
