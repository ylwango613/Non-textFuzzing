7バッチ全読み終了。全パーサー（hdr_dynamic_metadata.c, dynamic_hdr_vivid.c, dovi_isom.c, matroskadec.c, mov.c）の上限チェックと正しいalloc関数使用を確認しました。

**分析結果まとめ**：

1. `print_pkt_side_data`（行1104-1170）での複数のside data typeで`sd->size`検証なし→ **defense-in-depthの欠如**だが、全demuxerが`av_stereo3d_alloc_size()`/`sizeof(*ast)`等で正確なサイズを使用するため、既存パスでは非到達
2. `read_interval_packets`（行1737-1746）での`ifile->streams`未拡張→ `selected_streams[new_index]==0`ガードで実際は非到達
3. HDRメタデータループ（num_windows, num_alternate_images等）→パーサーが[2,25]等に検証済み
4. `parse_read_intervals`のint overflow → コマンドライン引数（メディアファイル経由ではない）
5. `log_callback`のNULL deref → OOM条件のみ

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
