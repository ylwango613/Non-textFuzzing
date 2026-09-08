全コードパスの解析が完了しました。以下に各重点領域の確認結果をまとめます。

**解析ポイント1: `s->bits` の割り当てと `intlist_read` の `x` インデックス**
- 割り当て: `av_calloc(s->max_framesize * 8, sizeof(*s->bits))` (line 124)
- `x` は外部ループで最大 1 増分/1bit 消費。GetBitContext は `buf_size * 8 ≤ max_framesize * 8` bits。`x` は `max_framesize * 8` 未満で収まる。`get_bits_left ≤ 0` チェック(line 171-173)が先行して保護する。**安全** ✓

**解析ポイント2: `memcpy` / `memmove` 境界（line 322, 326）**
- `buf_size = FFMIN(pkt->size, s->max_framesize - s->bitstream_size)` → `buf_size ≤ max_framesize - bitstream_size`
- `s->bitstream_size = buf_size`（line 329）で正しく更新され、合計 ≤ `max_framesize`。 **安全** ✓

**解析ポイント3: `max_framesize` の整数計算（line 107）**
- `samples_per_packet`(uint16, ≤65535) × `nb_channels`(1 or 2) × `down_sampling`(uint8, ≤255) × 16 = 最大 534,765,600 → int32 に収まる。line 108-109 で上限チェック済み。**安全** ✓

**解析ポイント4: `s->samples[ch]` の読み書き範囲（lines 361-373）**
- 割り当て: `samples_per_packet * down_sampling` 要素。書き込みも同数。`state[i] = sample[offset - i]` で `offset - (n_taps - 1) ≥ 0`（line 104 の事前チェックによる保証）。**安全** ✓

**解析ポイント5: `av_calloc` のオーバーフロー保護**
- `size_mult()` による積のオーバーフローチェックあり。巨大な割り当ては NULL 返却で ENOMEM になる。**安全** ✓

**解析ポイント6: `extradata` フィールド由来の値**
- `n_taps`, `down_sampling`, `samples_per_packet` すべて明示的な境界チェック（lines 93-105）を通過後にのみ使用。**安全** ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
