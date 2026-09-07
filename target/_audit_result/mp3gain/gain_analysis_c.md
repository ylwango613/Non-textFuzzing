全てのコードを確認しました。分析結果を整理します。

**gain_analysis.c の分析サマリー:**

1. **静的バッファ (lines 117-128)**: `lstepbuf[MAX_SAMPLES_PER_WINDOW + MAX_ORDER] = 4811要素`、`lstep = lstepbuf + MAX_ORDER`、フィルタの書き込みは `lstep + totsamp + cursamples - 1` = `lstepbuf[10 + sampleWindow - 1]` = `lstepbuf[4809]` まで、バッファ内に収まる。

2. **filterYule/filterButter の負インデックスアクセス (lines 193-235)**: `output[-1]` ～ `output[-10]`、`input[-1]` ～ `input[-10]`を参照するが、`lstep = lstepbuf + MAX_ORDER` により `output[-10] = lstepbuf[0]` で境界内。

3. **memmove (lines 406-409)**: `totsamp == sampleWindow` のとき `loutbuf + sampleWindow` から `MAX_ORDER` バイトを移動。96kHz で `loutbuf[4800..4809]`、バッファサイズ4811内に収まる。

4. **num_samples の整数キャスト (line 314)**: `batchsamples = (long)num_samples`。オーバーフローしてもループ不実行となるだけで書き込みは発生しない。

5. **事前バッファ領域 (lines 322-329)**: `linprebuf + MAX_ORDER`への初期コピーは `num_samples < MAX_ORDER` のとき最大9要素で、`linprebuf[20]` 内に収まる。

6. **lines 415-423 のmemmove/memcpy**: num_samples に基づく移動量は MAX_ORDER を超えず、リングバッファとして安全に動作する。

7. **callerバッファ検証**: `AnalyzeSamples` が `left_samples[cursamplepos..cursamplepos+cursamples-1]` を読む範囲は `left_samples[0..num_samples-1]` に収まる。

全てのバッファ境界が静的に確定しており、入力依存のサイズ計算も `sampleWindow ≤ MAX_SAMPLES_PER_WINDOW` の制約内に収まることを確認。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
