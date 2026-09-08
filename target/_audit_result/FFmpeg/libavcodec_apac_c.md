以下に全分析を記録します。

**Group 1 (lines 1-100): 初期化・構造体**
- `block[32*2]` = 64バイト固定バッファ
- `bits_per_coded_sample` は 8-16 に制限（apac_init: 76-81行）
- `ch_layout.nb_channels` は 1-2 に制限
- `max_framesize=1024` で初回割り当て: `av_realloc_f(…, 1024 + AV_INPUT_BUFFER_PADDING_SIZE, 1)` = 正しい

**Group 2 (lines 102-165): バッファ管理**
- 行143のオーバーフローチェック: `(int64_t)s->bitstream_size + buf_size > INT_MAX/(16*8)` → `s->bitstream_size` の最大は `INT_MAX/128 ≈ 16.7M`
- 行151-158のrealloc: `s->bitstream_index + s->bitstream_size + buf_size + AV_INPUT_BUFFER_PADDING_SIZE` バイトを確保
- 不変式 `allocated = max_framesize + AV_INPUT_BUFFER_PADDING_SIZE` は一貫して維持される
- 行165の `memset(buf + buf_size, 0, AV_INPUT_BUFFER_PADDING_SIZE)` は常に確保済みバッファ内

**Group 3 (lines 167-263): デコードループ**
- `frame->nb_samples = s->bitstream_size * 16 * 8` → 最大 `(INT_MAX/128) * 128 = INT_MAX`（オーバーフローなし）
- `block_length` は `get_bits(gb, 4)` = 0-15のみ。S16P: 15×2=30バイト < block[64]、U8P: 15×1=15バイト < block[64]。OOB書き込みなし
- `bit_length` は行197-203で `[0,17]` にチェック済み。`get_bits_long(gb, 0)` は 0 を返す（安全）
- `get_bits_long` は 0-32ビットをサポート（実装確認済み）

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
