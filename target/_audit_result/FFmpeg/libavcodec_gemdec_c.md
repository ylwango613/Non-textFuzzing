`av_image_check_size2` の制約確認が完了しました（`w==0` および `stride*(h+128) >= INT_MAX` を拒否）。

---

以下に各コードパスの分析結果を整理します：

**分析1: `av_reallocp_array`（L258）**  
`planes * row_width` の積。`planes` は最大で TIMG の 15、`row_width` は `(avctx->width+7)/8`。`av_image_check_size2` が `8*w + 128*8 < INT_MAX` を保証するため、`w < INT_MAX/8 ≈ 268M`。これにより `15 * (268M+7)/8 ≈ 502M` < `INT_MAX`。オーバーフローなし。

**分析2: `PUT` マクロ（L279）**  
`row[state.pl * row_width + x]` の書き込み。`x` は `row_width - 1` まで、`state.pl` は `planes - 1` まで（`put_lines_bits` でリセット）。最大インデックスは `(planes-1) * row_width + (row_width-1) = planes * row_width - 1` で割り当て内。

**分析3: `put_lines_bits` の `pl_byte` OOB**  
`pl_byte = state->pl / 8`。PAL8（pixel_size=1、planes≤8）では pl_byte=0 固定で問題なし。BGR555（pixel_size=2、planes=15）では pl_byte が 0 か 1 になるが、書き込みオフセット `px*2+pl_byte` の最大は `(avctx->width-1)*2+1 = avctx->width*2-1` で `linesize[0] >= avctx->width*2` 内に収まる。

**分析4: `put_lines_bytes` の memcpy（L83）**  
コピー元サイズ `avctx->width * pixel_size`。`row` は `1 * row_width` で確保済みで、各パスで `row_width >= avctx->width * pixel_size` が成立。

**分析5: パターン境界チェック（L314）**  
`if (b > buf_end - pattern_size)` は `pattern_size` が最大 65535 (uint16_t) で、ヒープアドレスは十分に大きいためポインタアンダーフローは実質不可能。チェックは正常機能。

**分析6: `width=0` 経路**  
`av_image_check_size2` が `w==0` を拒否するため `avctx->width` が 0 になることはない。

**分析7: `b` ポインタ初期化**  
`b = buf + header_size * 2`。`header_size` は最大 65535 で積は 130770、int オーバーフローなし。`buf_size > header_size * 2` チェック（L111）により `b < buf_end` が保証。

全パスにおいて外部からトリガー可能なメモリ安全性の脆弱性は発見されなかった。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
