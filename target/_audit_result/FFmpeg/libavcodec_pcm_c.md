`avcodec_open2` が `FF_SANE_NB_CHANNELS = 512` の上限チェックを行うことを確認しました。これで全体の制約が明確になりました。

**分析完了：**

1. **Line 431 `n = channels * sample_size`** — 整数オーバーフローの理論的経路。ただし `avcodec_open2` が `nb_channels > 512` で `AVERROR(EINVAL)` を返すため、`channels` は最大 512 に制限される。512 × 8 (S64) = 4096 で 32-bit オーバーフローは発生しない。

2. **`ff_get_encode_buffer(avctx, avpkt, n * sample_size, 0)`** — `n * sample_size` が `int` としてオーバーフローしても、`int64_t` パラメータへ拡張後に `if (size < 0)` チェックで捕捉される。

3. **`DECODE_PLANAR`/`DECODE` マクロ** — 行 433–441 のアライメントチェックにより `buf_size` が `channels * sample_size` の倍数に切り詰められるため、`nb_samples` 計算とデータ書き込み量は一致する。

4. **LXF デコーダ** — `n *= 2 / channels` の分配法則による整数切り捨て不一致の懸念があるが、`buf_size` がアライメント済みのため `n = buf_size/5` は `channels` で割り切れ、書き込みサイズとバッファサイズは一致する。

5. **PARAM_CHANGE サイドデータ** — チャンネル数変更は `apply_param_change` ではサポートされておらず、実行中に channels を不正な値に変更することはできない。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
