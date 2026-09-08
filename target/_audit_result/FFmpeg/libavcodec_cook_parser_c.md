ファイル全体の分析が完了しました。以下が最終判断です。

- `cook_parse()` (L38-55): 62行のシンプルなパーサー。
- L46 の `AV_RB16(avctx->extradata + 4) / avctx->ch_layout.nb_channels` は `extradata_size >= 8` チェック済みで OOB 読み取りなし。`nb_channels` は非ゼロ確認済み（負数の場合は論理バグだが memory-safety ではない）。
- メモリ確保・`memcpy`・配列インデックスアクセスは一切なし。`*poutbuf` は入力 `buf` をそのまま返すのみ。
- `CookParseContext` は `int duration` 一つだけを持ち、overflowの余地なし。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
