I have now read the entire file in batches (lines 1–1479) and cross-checked all critical array bounds with the header constants. Here is the full picture of what was audited:

**Key bounds verified:**
- `bypassed_lsbs[MAX_BLOCKSIZE][MAX_CHANNELS]` — indexed by `pos + blockpos` (≤ MAX_BLOCKSIZE–1) and `mat` (< num_primitive_matrices ≤ MAX_MATRICES = 8 = MAX_CHANNELS): within bounds.
- `sample_buffer[MAX_BLOCKSIZE][MAX_CHANNELS]` — in `generate_2_noise_channels`, writes at `[i][maxchan+1]` and `[i][maxchan+2]`; function is only reachable when `!noise_type`, which constrains `max_matrix_channel ≤ 5` (see `read_restart_header` line 569–574), so `maxchan+2 = 7 = MAX_CHANNELS–1`: within bounds.
- `matrix_coeff[MAX_MATRICES][MAX_CHANNELS]` — inner loop in `read_matrix_params` runs `ch` from 0 to `max_matrix_channel+(0 or 2)`: in all valid combinations ≤ 7 < MAX_CHANNELS=8.
- `ch_assign[MAX_CHANNELS]` — guarded by explicit range check (`0 ≤ ch_assign ≤ max_matrix_channel`).
- `output_shift`, `quant_step_size`, `channel_params` — all indexed up to `max_channel ≤ 7 < MAX_CHANNELS`.
- `state_buffer[NUM_FILTERS][MAX_BLOCKSIZE+MAX_FIR_ORDER]` in `filter_channel` — `firbuf ± blocksize` stays within the allocated 168-element sub-array.
- `substream_data_len[MAX_SUBSTREAMS]` / `substream[MAX_SUBSTREAMS]` — both indexed by `substr < num_substreams ≤ MAX_SUBSTREAMS=4`.
- `huff_lsbs` shift in `get_bits_long` — when `codebook>0`, limited to 24; when `codebook=0`, max lsb_bits = 31, still within `get_bits_long` capacity.
- All integer arithmetic (sign_huff_offset, 1<<sign_shift, 1<<quant_step_size) stays within 32-bit range given the validated input ranges.

No externally-triggerable out-of-bounds write, heap overflow, stack overflow, or type-confusion reachable from a crafted MLP/TrueHD bitstream was identified.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
