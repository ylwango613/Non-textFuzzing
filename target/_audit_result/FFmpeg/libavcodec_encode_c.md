`ff_encode_add_stats_side_data` の全呼び出し箇所を確認しました。`error_count` は全て内部エンコーダ状態（0 または AV_NUM_DATA_POINTERS 以下の小さな値）から来ており、外部入力から制御できません。

**全セクションの分析まとめ:**

- **lines 62-135**: `ff_alloc_packet`/`ff_get_encode_buffer` — サイズ検証 `size < 0 || size > INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE` が適切に配置されている。
- **lines 137-202**: `encode_make_refcounted`/`pad_last_frame` — `memcpy` のサイズは既に検証済みのバッファから取得、`AV_FRAME_DATA_SKIP_SAMPLES` のサイド データは 10 バイト確保して 10 バイト書き込み。
- **lines 233-278**: `encode_set_packet_props` — `frame_sd->size >= 10` チェック後に bytes 0-9 を読み書き、問題なし。
- **lines 481-543**: `encode_send_frame_internal` — `src->nb_samples < pad_samples` 条件下で `out_samples` 計算（除算ゼロ・整数オーバーフローなし）。
- **lines 957-978**: `ff_encode_preinit` ループ — `sd_frame->size` を `av_packet_side_data_new` に渡し同サイズで `memcpy`、デスティネーション確保後にコピーで安全。
- **lines 1070-1093**: `ff_encode_add_stats_side_data` — `4+4+8*error_count` の整数計算は技術的に UB の可能性があるが、`error_count` は全呼び出し箇所でエンコーダ内部値（≤8）であり外部制御不可。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
