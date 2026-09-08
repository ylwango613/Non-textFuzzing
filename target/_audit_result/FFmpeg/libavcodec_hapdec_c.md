`snappy.c` を確認しました。`ff_snappy_uncompress` では `*size`（= `ctx->tex_size`）を上限として `len`（Snappy ヘッダの varint）を検証しています。各チャンクの `uncompressed_offset + uncompressed_size <= ctx->tex_size` は次元チェック後に保証されるため、アウトオブバウンドライトは発生しません。

主な調査ポイントの確認結果：

1. **`ctx->tex_size` 累積オーバーフロー**（行 215）: size_t 型で 64 ビット環境では実質不可能。32 ビット環境では理論的だが、次元チェック（行 287-291）でキャッチされる
2. **`chunk->uncompressed_offset = ctx->tex_size` の int 型トランケーション**（行 197）: tex_size の上限が av_image_check_size で~2^30 に制限されているため INT_MAX 超過は不可能
3. **`ff_snappy_uncompress` に `ctx->tex_size` を渡す問題**（行 236）: peek と uncompress が同じ varint を読み、`uncompressed_offset + uncompressed_size <= tex_size` が保証されているため OOB なし
4. **HAP_ST_SIZE_TABLE の `section_size % 4` バイト未消費**: gbc 位置と size カウンタのズレだが直接的メモリ安全問題なし
5. **section_size の負数チェック**: `ff_hap_parse_section_header` が `< 0` チェックを実施

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
