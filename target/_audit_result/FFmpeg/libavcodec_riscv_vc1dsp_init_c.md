After thoroughly reading the 79-line `vc1dsp_init.c` and all related assembly implementations (`vc1dsp_rvv.S`, `startcode_rvv.S`, `startcode_rvb.S`), plus tracing every function into its callers in `vc1dec.c` and the `VC1DSPContext` struct definition, my findings are:

- `ff_vc1dsp_init_riscv()` only assigns function pointers; all array indices (`[0][0]`, `[1][0]`) are within the declared `[2][16]` bounds — no OOB write.
- `ff_vc1_unescape_buffer_rvv`: removes escape bytes, so output ≤ input. Callers in `vc1dec.c` allocate `dst = av_mallocz(buf_size + AV_INPUT_BUFFER_PADDING_SIZE)`, where `buf_size` always covers `size` — no overflow.
- `ff_vc1_inv_trans_*_rvv`: fixed 4×4 / 4×8 / 8×4 / 8×8 transforms on a 64-element `int16_t` block; furthest access is `a0 + 7×8×2 = +112` bytes, well within the 128-byte block — no OOB.
- `ff_avg_pixels{8,16}x{8,16}_rvv`: processes exactly 8 or 16 rows of 8 or 16 bytes respectively; only enabled when `ff_rv_vlen_least(128)` — no OOB.
- `ff_startcode_find_candidate_rvb/rvv`: read-only scan functions with aligned access optimization that cannot cross page boundaries — no exploitable OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
