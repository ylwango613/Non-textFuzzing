The decoder (`sbcdec.c`) uses its own `sbc_decoder_state` structure and does **not** call any `SBCDSPContext` functions from `sbcdsp.c`. The `sbcdsp.c` DSP functions are encoder-only.

**Summary of analysis findings:**

1. **`x[-7]` write at line 256** (`sbc_enc_process_input_8s`): Suspicious negative-index write. Traced exhaustively: in the only reachable code path (mSBC mode, `nsamples=120`, `position=256` after wraparound), the main loop reduces `position` to 144, then `position -= 8 → 136`, giving `x[-7] = X[c][129]`. Index 129 is well within `[0..327]`. This is intentional PCM sample reordering, not a bug.

2. **`sbc_analyze_simd` stack arrays** `t1[8]`/`t2[8]`: Maximum access indices are `(subbands-1)=7` and `(subbands/2-1)*2+1 ≤ 7` for both `subbands=4` and `subbands=8`. All within bounds.

3. **`sbc_calc_scalefactors_j` inner arrays**: `sb_sample_j[16][2]` accessed with `blk < blocks ≤ 15`. Safe.

4. **PCM read offsets**: Maximum read offset `30*nchannels + 2*c = 62` bytes, within the frame size enforced by `av_frame->nb_samples * channels * 2 >= codesize`.

5. **Decoder isolation**: `sbcdec.c` never calls `ff_sbcdsp_init` or any `SBCDSPContext` function pointer. The attack surface through crafted SBC files does not reach this code.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
