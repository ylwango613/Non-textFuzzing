全体解析が完了しました。以下の観点を詳細に検証しました。

**検証項目まとめ：**

1. **`dss_sp_add_pulses`の`pulse_pos[i]`** : `get_bits_long(31)`で読み取った`combined_pulse_pos`は最大`2^31-1=2147483647 < C72_binomials[7]=3379081753U`のため、外部入力では`else`分岐に入らず、`pulse_dec_mode=1`パスのみ実行。そこでは`pulse_idx`が71から0まで減少（`table[pulse][0]=0`がアンダーフローを阻止）し、`pulse_pos[i]`は常に0..71の範囲内。

2. **`dss_sp_gen_exc`の`pitch_lag`** : `pitch_lag[0] = (combined_pitch % 151) + 36` → 36..186。調整後も各サブフレームのpitch_lagは36..186の範囲内。`p->history[187]`への最大アクセスは`history[186]`で境界内。

3. **`dss_sp_unpack_filter`のfilter_idx** : `get_bits(5/4/3)`で各インデックスが0..31/0..15/0..7に制限され、`dss_sp_filter_cb[14][32]`の範囲内。

4. **`dss_sp_update_state`の`excitation[294]`** : ループのoffset計算は1〜293の範囲で推移し、境界を超えない。`working_buffer[4][72]=288`要素への264要素読み書きも境界内。

5. **`dss_sp_32to16bit`の出力** : `DSS_SP_SAMPLE_COUNT = 66*4 = 264`サンプル分確保されており、書き込み量と一致。

6. **各固定配列インデックス** : `gain`(6bit→0..63, `dss_sp_fixed_cb_gain[64]`内)、`pulse_val`(3bit→0..7, `dss_sp_pulse_val[8]`内)。

7. **スタックバッファ** : `noise[72]`はsize=72で確保・使用され一致。`tmp_buf[15]`は0..14でアクセス。

外部入力で到達可能なメモリ安全性の脆弱性は発見されませんでした。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
