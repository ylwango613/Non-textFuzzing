`av_image_check_size2` が `avcodec_open2` 内で呼び出されることが確認できた。この関数は `(8*w + 1024) * (h + 128) >= INT_MAX` を条件にサイズを拒否するため、最大許容解像度は約 16384 × 16000 程度に制限される。その範囲では：

- `rawsize = height * FFALIGN(width,2) * 2` の最大値 ≈ 524,288,000 (INT_MAX の 1/4 以下、オーバーフローなし)
- `height * (width * 3 / 4)` の最大値 ≈ 196,608,000 (オーバーフローなし)

整数オーバーフローを起こすには ~350M 以上の次元が必要だが、`avcodec_open2` のサイズバリデーションがそれを事前に遮断する。他の検査項目：

- ニブルインデックス (0-15) による `y_table`/`u_table`/`v_table` アクセスは常に 16 エントリ内に収まる
- UYVY422 パスの memcpy は `linesize = rawsize / height` であるため buf 境界を超えない
- YUV411P パスのポインタ増分は frame->linesize[] に基づき正常範囲内

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
