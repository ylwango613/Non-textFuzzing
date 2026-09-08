全コードパスの精査が完了しました。要点をまとめます。

- `expval_table_fixed[512]` へのインデックス (`exponent`) は gain/scalefactor/shift の組み合わせ計算で最小 6〜8、最大 445 に収まり、範囲内 (0-511)。
- `g->scale_factors[40]` への書き込みは LSF テーブル (`ff_lsf_nsf_table`) の行和が最大 36 で上限内。
- `g->sb_hybrid[576]` への huffman デコード書き込みは `s_index ≤ 572` (+4) の while 条件で保護。
- `division_tab3[64]`/`division_tab5[256]`/`division_tab9[2048]` へのアクセスは対応ビット数 (5/7/10 bit) で生成される v 値が常に範囲内。
- `ff_band_size_long[9][22]`/`ff_band_size_short[9][13]` のインデックス (`sample_rate_index` = 0-8, band index ≤ 21/12) は範囲内。
- `decode_frame_mp3on4` の `AV_RB16(buf)` は FFmpeg の AV_INPUT_BUFFER_PADDING_SIZE (64バイト) ゼロパディング保証により、`len=0` 時の読み越しは実害なし。
- mp3on4 デコーダの `mp3decctx[5]` 配列へのアクセスは frames ≤ 5 で保護。
- `last_buf[LAST_BUF_SIZE]` への memcpy は `av_clip` で厳密に bounded。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
