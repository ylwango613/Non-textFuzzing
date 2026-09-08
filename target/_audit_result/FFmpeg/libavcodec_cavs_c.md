完全な3バッチ読み込みと調査が完了しました。最終的な分析を整理します。

**Batch 1 (行1-400) 調査結果:**
- `ff_cavs_filter()`: `top_border_y[mbx*16±offset]`, `top_border_u[mbx*10±offset]` のすべてのアクセスは `(mb_width+1)*16` / `mb_width*10` の割り当てに対して範囲内
- `ff_cavs_load_intra_pred_luma()`: `top[x+y+2]` max index=16 < top[18] の境界、`C_AVAIL` ガードで `(mbx+1)*16` アクセスも安全
- `modify_pred()`: `pred_mode_Y[4,5,7]` は decode_mb_i で 0-7 の範囲に設定され、`left_modifier_l[8]` / `top_modifier_l[8]` インデックスが境界内

**Batch 2 (行400-700) 調査結果:**
- `mc_dir_part()`: 境界外アクセスは `emulated_edge_mc` で保護。`h->DPB[mv->ref]` は ref=0 または 1 のみ
- `ff_cavs_mv()`: `mv[]` 配列インデックス 0-22 はすべて 24 要素配列の範囲内。`h->dist[mvP->ref]` は ref=0/1 で安全
- `ff_cavs_init_mb()`: `top_mv[h->mbx*2+i]` (i=0..2) の max は `mb_width*2` で割り当て `mb_width*2+1` に対して安全

**Batch 3 (行700-853) 調査結果:**
- `ff_cavs_init_top_lines()`: `mb_width * mb_height` は 14-bit 寸法フィールドにより最大 1024×1024=1,048,576 で `int` 範囲内。`av_calloc` の内部 `av_size_mult` 検査も通過
- `mv_pred_direct()`: `direct_den[col_mv->ref]` — `col_mv` は P フレームの `store_mvs()` でのみ書き込まれ、ref は常に 0 または 1

**追加確認:**
- `decode_residual_block()`: VLC テーブルの `max_run` は最大 26 で `level_add[27]` の範囲内。`inc_limit=INT_MAX` の番兵でテーブル末端超えを防止
- `dequant()`: `pos > 63` チェックで `scantab[pos]` および `dst[64]` への OOB を防止
- すべての `col_type_base` / `col_mv` アクセスは `mbidx < mb_width*mb_height` で境界内

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
