**Summary of analysis:**

- **Input validation**: `ra288_decode_init` enforces `block_align == 38` exactly; `ra288_decode_frame` further validates `buf_size >= block_align`.
- **Bit reads**: `get_bits(&gb, 3)` yields 0–7 (indexes `amptable[8]`); `get_bits(&gb, 6+(i&1))` yields 0–63 or 0–127 (indexes `codetable[128]`). Both in-bounds.
- **Array accesses in `decode()`**: all `sp_hist`, `gain_hist`, `buffer`, `sp_lpc`, `gain_lpc` accesses are bounded by hardcoded constants, verified element-by-element.
- **`do_hybrid_window`**: The `vector_fmul` call uses `FFALIGN(order+n+non_rec, 16)` as length. For the gain path this is `FFALIGN(38,16)=48`, reading 10 floats beyond `gain_hist[38]` into adjacent `gain_rec` — a technical intra-struct OOB read. However, the computed values land in `work[38..47]`, which are never subsequently read by any `convolve` call (max index reached is `work[37]`). No crash, no attacker-reachable write.  
- **`compute_lpc_coefs`**: writes to `lpc[0..order-1]`; sp_lpc has 48 slots (order=36) and gain_lpc has 16 slots (order=10) — both within bounds.
- **`ff_celp_lp_synthesis_filterf`**: called with `block=sp_hist+106`, writing 5 samples into `sp_hist[106..110]` — within bounds.
- **`memmove` calls**: all source and destination ranges verified within declared array extents.
- All size parameters originate from compile-time constants, not from the untrusted bitstream. No user-controlled value reaches any allocation size or array index.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
