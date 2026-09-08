**分析結果**

**golomb.c**（174行）：ファイル全体が静的定数ルックアップテーブル（`const uint8_t`/`const int8_t` 配列）のみ。関数なし、メモリ確保なし、ポインタ演算なし。

**golomb.h**（622行）のインライン関数群を精査：

- `get_ue_golomb`/`get_ue_golomb_31`：`buf >>= 32-9` → インデックス範囲 0..511、テーブルサイズ 512 → 安全
- `get_ue_golomb_long`：`buf=0` 時 `av_log2(0)=0`（FFmpeg実装）→ `log=31`、`get_bits_long(gb,32)` → 有効
- `get_interleaved_se_golomb`：`for(log=31; ... ; log--)` ループで log が負になり `buf >> (-1)` という UB は理論上存在するが、GetBitContext のバウンダリーセーフなビットリーダー経由のためメモリ破壊には至らない
- `get_ur_golomb_shorten`：`limit=INT_MAX` で整数オーバーフローは生じ得るが、ビットストリーム終端チェックで早期終了するため実際のメモリ破壊にはつながらない
- 全関数ともビット読み出しは GetBitContext マクロ経由で境界が保護されており、外部バッファへの直接書き込みは一切行わない

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
