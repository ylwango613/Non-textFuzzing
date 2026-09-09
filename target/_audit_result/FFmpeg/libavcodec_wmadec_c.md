After reading all sections of wmadec.c and tracing through wma.c, wma.h, wmadata.h, and wma_freqs.c, I completed the analysis. Here is the definitive summary of findings:

**Group 1 (lines 1-250)**: Initialization, VLC setup — all bounds checked.

**Group 2 (lines 337-390, decode_exp_vlc)**: The Duff's device writes `n` values without checking against `q_end`. Potential OOB-read of `exponent_bands[bsize]` for sample_rate ≈ 50000 (bands don't cover full block_len). However, any resulting over-writes into `exponents[1][*]` remain within the contiguous `exponents[MAX_CHANNELS][BLOCK_MAX_SIZE]` array (4096 elements total), bounded by the identity: `q_end + max_n ≤ block_len + BLOCK_MAX_SIZE ≤ 2·BLOCK_MAX_SIZE = 4096`. No heap OOB.

For WMAv1 with `use_variable_block_len` and bsize > 0: `exponent_bands[bsize]` is all-zero (av_mallocz). Reads past the 25-element boundary into adjacent struct rows and eventually into `high_band_start`, `coefs_end`, etc. Values read (up to ~1864) drive Duff's device writes, but the mathematical bound holds: all writes stay within `exponents[2][2048]`.

**Group 3 (lines 832-1004, wma_decode_superframe)**: `last_superframe_len += 8*buf_size - 8` (line 900) stores bit-count instead of byte-count. On the next normal call, `q = last_superframe + last_superframe_len` uses this as a byte offset (e.g., 32760 instead of 4095). However, the check at line 927 (`last_superframe_len + (bit_offset+7)/8 > MAX_CODED_SUPERFRAME_SIZE`) mathematically prevents `q` from exceeding `last_superframe + MAX_CODED_SUPERFRAME_SIZE`. The memset and byte writes remain within the 32832-byte buffer. The `init_get_bits` declares ~262080 bits on a 262656-bit buffer — within bounds. The decoder reads zeros (av_mallocz'd), triggers VLC error (code 0 → `last_exp = -24`, check fires AVERROR_INVALIDDATA), and goes to `fail` without any memory corruption.

**Group 4 (lines 427-485, ff_wma_run_level_decode)**: `iptr[offset & coef_mask]` masks all writes within block_len. `level_table` and `run_table` accesses are bounded by hardcoded VLC table size. No OOB.

**Group 5 (wma_window, frame_out indexing)**: Maximum write position `= index + 2·block_len ≤ 2·BLOCK_MAX_SIZE = 4096 = sizeof(frame_out[ch])`. Within bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
