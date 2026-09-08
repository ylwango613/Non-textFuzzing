`ME_MAP_SHIFT = 3`、`ME_MAP_SIZE = 64`、`ME_MAP_MV_BITS = 11` と確認。ファイルは `motion_est.c` にのみインクルードされる encoder 専用コードです。

**バッチ1 (1-400行) の分析:**
- `mv_penalty` は `c->mv_penalty[f_code] + MAX_DMV` を基点とした中央配置アレイで、有効インデックスは `[-MAX_DMV, MAX_DMV]`。
- `qpel_motion_search` の `memmove` (行 283-284) は i=7 時に 0 バイトコピーで安全。
- スコア計算オーバーフロー (行 267, 319) は "FIXME" コメントで承認済みだが、メモリ安全性には影響しない。

**バッチ2 (401-800行) の分析:**
- `SAB_CHECK_MV` (行 655): `((ay)<<ME_MAP_MV_BITS)` が signed integer の left shift → UB だが、`index` は `& (ME_MAP_SIZE-1)` で 0-63 に必ずマスクされるため実際の OOB アクセスは発生しない。
- `sab_diamond_search` (行 681) の `minima[MAX_SAB_SIZE]`: `minima_count = FFABS(c->dia_size)` が `MAX_SAB_SIZE=64` を超えればスタック OOB。ただし `dia_size` はユーザー指定のエンコーダオプション (`-dia_size`) で制御され、入力メディアファイルからは読み取られない。

**バッチ3 (800-1048行) の分析:**
- `epzs_motion_search_internal` / `epzs_motion_search2`: `last_mv[ref_mv_xy±1]` / `last_mv[ref_mv_xy±ref_mv_stride]` アクセス（行 931-941, 1034-1039）は上位関数の `s->c.mb_y + 1 < s->c.end_mb_y` 等でガードされている。

**攻撃面評価:**  
`motion_est_template.c` は `motion_est.c` のみにインクルードされる encoder 専用テンプレート。`ffmpeg -i <crafted_file> -f null -`（デコード専用）では一切実行されない。トランスコード時 (`ffmpeg -i <crafted_file> -c:v mpeg4 output.mp4`) でエンコーダが動くが、`xmin/xmax`・`f_code`・`dia_size` 等の境界パラメータはエンコーダオプションで決まり、入力ファイルの内容で直接制御できない。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
