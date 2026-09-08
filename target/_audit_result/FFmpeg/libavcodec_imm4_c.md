全ての主要なコードパスを精査した。検証結果のまとめ：

- **`decode_block()`**: `i += len` 後に `if (i >= 64) break` で境界チェック済み。`idct_permutation[64]` は 64 要素配列で、i < 64 保証済み。`s->block[0..5][0..63]` アクセスも安全。
- **`intra_cb[s->lo]` / `inter_cb[s->lo]`**: `s->lo > 2` の場合 `AVERROR_INVALIDDATA` を返す（行 208–210, 263–265）。越境なし。
- **非 16 倍数の width/height による idct_put OOB の疑念**: `avcodec_align_dimensions2()` が `AV_PIX_FMT_YUV420P` に対して `h_align=32`, `w_align=16` を設定し（utils.c 行 244–245: `h_align = 16 * 2`）、バッファを 32 行単位に切り上げ確保する。ループは y 軸 16 ステップで `y+15` まで書き込むが、最大アクセス行 ≤ FFALIGN(height, 32) - 1 の範囲内に収まることを数値確認済み。x 軸も w_align=16 が担保。OOB は成立しない。
- **avpkt->data[8], avpkt->data[10] アクセス**: 行 372 で `avpkt->size <= 32` の場合早期 return。インデックス 10 まで安全。
- **s->hi/lo の整数演算**: `s->lo * 2` = 最大 131070 (int 範囲内)。`factor * factor2` の int16_t への切り捨ては値破壊だが memory safety 問題ではない。
- **prev_frame 次元保護**: サイズ変更は I フレームのみ許可、P フレームでサイズ変更があれば `AVERROR_INVALIDDATA` で終了（行 444–451）。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
