ファイルを全体通読し、主要な関数・データフロー・境界チェックを詳細に検証しました。

**分析した主な箇所：**

1. **`read_map()`（行128-149）**：`t->elements` の最大値は `DST_MAX_ELEMENTS - 1 = 11` にバウンドされており、`map[]` の配列範囲内（`DST_MAX_CHANNELS = 6`）。

2. **`read_table()`（行169-203）**：
   - `t->length[i] = get_bits(gb, length_bits) + 1` → fsets: 最大128、probs: 最大64。
   - `t->coeff[i]` は `int coeff[DST_MAX_ELEMENTS][128]`、インデックス j は最大 127。境界内。

3. **`read_uncoded_coeff()`（行159-167）**：`elements = t->length[i]` ≤ 128、書き込み先 `t->coeff[i]` も 128 要素配列。オーバーフロー無し。

4. **`build_filter()`（行237-259）**：`j * 8 + l` の最大値は `15*8+7 = 127`、コアフィールド内。`av_clip` による `total` のクランプも正常。

5. **`decode_frame()` のバッファ書き込み（行401）**：
   - `dsd[(i >> 3) * channels + ch]` の最大インデックス = `(samples_per_frame/8 - 1) * channels + channels - 1 = frame->nb_samples * channels - 1`。
   - これは `ff_get_buffer()` / `av_fast_malloc()` で確保したバイト数と厳密に一致。

6. **整数オーバーフロー検証**：
   - `decode_init()` で `sample_rate ≤ 512 * 44100` を保証。
   - `samples_per_frame` 最大値 = 2,408,448 → `unsigned int` に収まる。
   - `frame->nb_samples * channels` 最大値 ≈ 1,806,336 → `int` 範囲内。

7. **`av_fast_malloc` サイズ**：最大 1,806,336 bytes、引数の型変換も問題なし。

全てのアレイアクセス・メモリ確保・ループ境界が適切に検証・クランプされており、外部から制御可能なフィールドによるメモリ安全性違反は確認できませんでした。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
