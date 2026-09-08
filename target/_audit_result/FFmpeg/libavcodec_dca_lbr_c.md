全ファイルを5回に分けて読み込みし、すべての関数・データフロー・配列アクセスを精査した。最終確認として、`ff_dca_corr_cf` と `f_delt` の上限、`ff_dca_grid_1_weights` アクセス、`alloc_sample_buffer` の整数乗算、`parse_tonal` の `main_ch` 範囲なども確認した。

**各主要経路の結論：**

- `alloc_sample_buffer`: `nsamples` = 144 × 6 × 32 = 27648。`sizeof(float)` 乗算も `int` 範囲内でオーバーフローなし。
- `parse_tonal` の `main_ch`: `get_bitsz(ch_nbits)` で `nchannels_total` より大きい値を得る可能性があるが、`amp[]/phs[]` は `DCA_LBR_CHANNELS_TOTAL=32` の大きさのスタック配列で常に境界内。
- `decode_grid` の `grid_1_scf[ch][g1_sb+1]`: `g1_sb` 最大値は10、+1で11、配列第2次元は `[12]` → 境界内。
- `synth_tones` の `values[x_freq+5]`: 検証済み `x_freq <= nsubbands*4-6`、`values` は `DCA_LBR_SUBBANDS*4=128` フロート → 最大インデックス127、境界内。
- `ff_dca_lbr_filter_frame` の `ch_conf` と `reorder[ch2]`: `ch2 < nchannels`（最大5）ガードにより `reorder[5]` へのアクセスは阻止される。
- `nsubbands` の上限: `sample_rate > 48000` を拒否するため `freq_range` 最大2、`nsubbands` 最大32 = `DCA_LBR_SUBBANDS`。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
