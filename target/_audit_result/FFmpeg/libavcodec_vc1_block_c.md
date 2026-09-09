After reading all 2979 lines in five batches and cross-checking table sizes against every access site, let me do one final check on the escape-mode coefficient paths and `vc1_delta_level_table` bounds.

The `vc1_delta_level_table[AC_MODES][31]` is indexed by `run` from non-LAST VLC entries. Looking at the data:
- Maximum run in non-LAST entries across all coding sets: 26 (coding set 5, visible at line 100–101). 26 < 31 ✓  
- `vc1_last_delta_level_table[AC_MODES][44]` indexed by `run` in LAST entries: max run across all sets is 43 (coding set 3, line 121). 43 < 44 ✓  
- `vc1_last_delta_run_table[AC_MODES][10]` indexed by `level` in LAST entries: max level observed is 8 (coding set 3, line 133). 8 < 10 ✓  
- `ff_vc1_dqscale[63]` indexed as `[q1-1]` where q1 ≤ 62 ✓  
- `ff_wmv3_dc_scale_table[32]` indexed by FFABS(mquant) ≤ 31 ✓  
- ZZ table accesses all gated by `if (i > 63) break` / `if (i > 31) break` / `if (i > 15) break` before access ✓  
- `block[k << sh]` with k∈[1,7], sh∈{0,3}: max index = 7<<3 = 56 < 64 ✓  
- `left_blk_idx = -1` initial value: every access guarded by `if (s->mb_x)` ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
