全ての調査が完了しました。以下の点を深く検証しました：

1. **`vlcdec_lookup[num_bits][value]`** (line 234): num_bits は huffsyms の最大値 0x7E から高ニブル = 7 に限定される。`get_bits(7)` で value は [0,127]。`vlcdec_lookup[7]` の宣言幅は 64 だが、cast `(int8_t*)vlcdec_lookup[7]` で [64..127] アクセスは row 8 (index 8) に入り込む。しかし配列全体 `[9][64]` = 576 バイト内の offset 7*64+127=575 (最終バイト) まで — 外側配列を超えない。技術的 UB だが実メモリ破損なし。

2. **`swap_buf_size` / `av_fast_padded_malloc`** (line 330, 395): `buf_size > MIMIC_HEADER_SIZE` 確認後に減算。`av_fast_padded_malloc` は `SIZE_MAX - AV_INPUT_BUFFER_PADDING_SIZE` との比較チェックあり。安全。

3. **`bswap_buf` 書き込み範囲** (line 399–401): swap_buf に `swap_buf_size + padding` バイト確保、書き込みは `swap_buf_size >> 2` 個の uint32 = `swap_buf_size & ~3` バイト ≤ swap_buf_size。安全。

4. **`num_coeffs` (byte, 0–255)** + `pos >= 64` チェック (line 227): `vlc_decode_block` 内で pos ≥ 64 で即 AVERROR_INVALIDDATA。OOB なし。

5. **width/height 検証** (line 356–360): 160×120 または 320×240 のみ許可。任意寸法でのオーバーフロー不可。

6. **backref ポインタ算術** (line 279–287): plane==0 (luma) 専用パス。`frames` 配列は常に `& 15` でマスク、16 要素内に収まる。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
