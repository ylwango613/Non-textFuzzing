All `src` scan tables (`ff_zigzag_direct`, WMV1 tables, prores scan tables, and `idct_permutation`) have values strictly in [0, 63]. The `permutation[j]` access in `ff_permute_scantable` is always bounded. All file-derived data at call sites is used only as the `permutation` argument (read values, not indices), and its 64-byte availability is checked before the call. The remaining functions (`ff_put_pixels_clamped_c`, `ff_add_pixels_clamped_c`, `put_signed_pixels_clamped_c`, etc.) operate on fixed 8×8 blocks with hardcoded loop bounds. `ff_idctdsp_init` only assigns function pointers from an internal enum with no heap allocation or external-data indexing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
