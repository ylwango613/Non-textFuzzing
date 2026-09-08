全1368行を3バッチで読み終え、`mv_predictor`/`ref` 配列境界、`er_temp_buffer` レイアウト、`guess_dc` のメモリ確保、各フィルタのフレームバッファアクセスをすべて確認しました。以下に主要な調査結果を記録します。

**`mv_predictor[8]`/`ref[8]` の境界**（行509-643）：pred_count の最大値は隣接4MBから+2（mean/median）+1（zero MV）+1（last MV）= 8。書き込みインデックスは最大7（mv_predictor[7]）、ループも `j < 8` で配列サイズ内。OOBなし。

**`er_temp_buffer` レイアウト**（行426-428）：blocklist × mb_stride×mb_height×8 + next_blocklist × 同×8 + fixed × 同×1 = 17バイト/MB。`av_malloc_array(mb_array_size, 4*sizeof(int)+1)` = `mb_array_size * 17` バイト。完全一致。av_assert0（行737）も確認。

**`guess_dc` の確保**（行161-162）：`av_malloc_array` は内部でオーバーフローチェック済み。アクセスパターン `col[b_x + b_y*stride][j]` は `b_x < w ≤ stride` より最大インデックス < stride×h。安全。

**`ff_er_frame_start` memset**（行817-818）：サイズ `mb_stride * mb_height` は `ff_er_init` の allocと同じ計算。一致。

**水平/垂直ブロックフィルタ**（行260-393）：最大アクセスはフレームバッファ `linesize[0] * mb_height * 16` バイト内に収まる。

**`ff_er_init` の型変換**（行44）：`unsigned mb_array_size = s->mb_height * s->mb_stride` は 64bit×32bit→64bit乗算後に32bitへ暗黙変換される可能性があるが、コーデックレベルの次元制限（最大幅・高さ数千px）により積がUINT_MAXを超えることはなく、実際には到達不可能。

全ての箇所において、外部から制御可能なフィールドがメモリ破壊に直接繋がるパスは確認されませんでした。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
