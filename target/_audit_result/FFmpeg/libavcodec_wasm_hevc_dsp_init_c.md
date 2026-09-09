The file is 59 lines. After verifying the `HEVCDSPContext` struct definition:

- `idct[4]` — accessed at indices 0–3 ✓ (within bounds)
- `sao_band_filter[5]` — accessed at indices 0–4 ✓ (within bounds)
- `sao_edge_filter[5]` — accessed at indices 0–4 ✓ (within bounds)

The function only sets hardcoded function pointers; it performs no memory allocation, no arithmetic on untrusted data, and does not parse any external input. There are no reachable memory-safety issues in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
