I have now completed a thorough multi-pass analysis of all 1486 lines of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/ilbcdec.c`, tracing every array access and its bounds:

**Summary of findings per analysis group:**

1. **unpack_frame() (lines 129–270)**: Bit reading is entirely via `GetBitContext` which enforces buffer bounds. All struct field writes use fixed indices within `ILBCFrame` (cb_index[15], gain_index[15], idx[58]).

2. **lsf_dequantization() (lines 285–311)**: `lsf[0]` = 6-bit (0–63), `lsf[1/2]` = 7-bit (0–127). Codebook sizes are exactly 64, 128, 128. All accesses to `lsf_codebook[1088]` stay within bounds.

3. **state_construct() (lines 525–603)**: `ifm = get_bits(gb, 6)` → 0–63; `frg_quant_mod[64]` is correctly sized. `ilbc_state[idx[j]]` where `idx[j]` is 0–7 (3-bit compose); `ilbc_state[8]` exactly matches. Stack buffers `sampleValVec/sampleMaVec[126]` accommodate `2*STATE_SHORT_LEN_30MS+LPC_FILTERORDER=126`. Negative-indexing in `filter_mafq12`/`filter_arfq12` is by design — surrounding `LPC_FILTERORDER`-word prefix is always zeroed first.

4. **decode_residual() (lines 771–870)**: `encbits->start` validated to 1–5 at line 1373–1374. With BLOCKL_MAX=240, mode-30 max access to `decresidual` = index 239 (exact boundary). `reverseDecresidual = s->enh_buf[643]` — max write index 159. `syntdenum` access max = index 54 in array of 66.

5. **get_codebook() (lines 651–720)**: All three index branches (`index < lMem-cbveclen+1`, `index < base_size`, else) produce non-negative `memIndTest` and keep `create_augmented_vector` lag values positive (20–39). The `mem[-CB_HALFFILTERLEN]` zeroing and backward-filter reads are within `prevResidual[240]`.

6. **gain_dequantization() (line 605–609)**: stage 0→`gain5[33]` (max index 31), stage 1→`gain4[17]` (max index 15), stage 2→`gain3[9]` (max index 7). All within bounds.

7. **do_plc() / xcorr_coeff()**: All `prevResidual` accesses bounded by `block_samples` with negative-pick guards; xcorr search stays within `decresidual`.

8. **ilbc_decode_init()**: `block_samples`, `nsub`, `state_short_len` are set from known constants at init — never from the stream.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
