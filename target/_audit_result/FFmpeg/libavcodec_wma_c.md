After thorough multi-pass analysis of `wma.c` and all reachable call paths—including `init_coef_vlc`, `ff_wma_init`, `ff_wma_run_level_decode`, the superframe handling in `wmadec.c`, and the WMAPro call path—here are my findings:

**Group 1 (lines 1–77, `init_coef_vlc`):** Uses hardcoded `vlc_table->n` (not attacker-controlled). `av_malloc_array(n, ...)` is bounds-safe; inner loop indices bounded by constants from `wmadata.h`.

**Group 2 (lines 79–351, `ff_wma_init`):** `exponent_high_bands[k][j++]` writes—`j` is bounded by the number of frequency bands above `high_band_start[k]`, which I calculated numerically for all valid sample rates (8000–50000 Hz). Maximum observed `j` ≤ 7–8, well below `HIGH_BAND_MAX_SIZE = 16`. The `/* XXX: find exact max size */` comment is conservative; the bound holds in practice. The UB float-to-int cast for `byte_offset_bits` (line 141) is caught by the `+ 3 > MIN_CACHE_BITS` guard.

**Group 3 (lines 427–485, `ff_wma_run_level_decode`):** Masking `offset & coef_mask` (`coef_mask = block_len - 1`, always a power-of-2 per `1 << block_len_bits`) guarantees writes stay in `[0, block_len-1]` ⊆ allocated buffer size. Post-loop overflow check detects malformed streams.

**Superframe handling (`wmadec.c:886–984`):** The `last_superframe_len += 8*buf_size - 8` at line 900 is a bits/bytes inconsistency (correctness bug), but the compensating bound check `last_superframe_len + buf_size - 1 ≤ MAX_CODED_SUPERFRAME_SIZE` prevents any write beyond offset 32767. After one `nb_frames==0` call, `last_superframe_len` inflates 8×, causing all subsequent calls to be rejected—no OOB path exists.

**WMAPro call path:** `subframe_len` is always `samples_per_frame >> i` (power of 2, range 64–8192), masking is sound, `ci->coeffs` array covers full `WMAPRO_BLOCK_MAX_SIZE`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
