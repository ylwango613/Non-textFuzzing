`mathtables.c` is a pure static-data file (163 lines). It contains only compile-time constant lookup tables: `ff_square_tab[512]`, `ff_inverse[257]`, `ff_sqrt_tab[256]`, `ff_crop_tab[256 + 2*MAX_NEG_CROP]` (where `MAX_NEG_CROP=1024`, giving 2304 bytes, matching the `times1024` macro data exactly), `ff_zigzag_direct[64]`, `ff_zigzag_scan[17]`, and `ff_log2_run[41]`.

There are no functions, no dynamic memory allocations, no external input parsing, no `malloc`/`memcpy`/`realloc` calls, and no runtime code of any kind. All array sizes are compile-time constants and the initializer data matches the declared sizes exactly.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
