全関数を精査します。

**Pass 1: `adx_encode`（行 38-97）**
- ループは `j < 32`、`i += channels`(channels≤2) → 最大インデックス `wav[31*channels]`
- ch=0：wav[0], wav[2], ..., wav[62] アクセス
- ch=1：(samples+1)[62] = samples[63] アクセス
- フレームは `BLOCK_SAMPLES * channels = 32 * 2 = 64` 個の int16_t → インデックス 0〜63 は有効
- `AV_WB16(adx, scale)` → 2バイト書き込み
- `init_put_bits(&pb, adx+2, 16)` → 32回 4-bit × = 128bit = 16バイト → BLOCK_SIZE(18) = 2+16 に一致

**Pass 2: `adx_encode_header`（行 101-122）**
- `bufsize` パラメータを受け取るが一切使用しない（dead parameter）
- bytestream_put_* で計 2+2+1+1+1+1+4+4+2+1+1+4+4+2+6 = 36 バイト書き込み = HEADER_SIZE
- 呼び出し元は `!c->header_parsed * HEADER_SIZE` を含む `out_size` を確保済み → オーバーランなし

**Pass 3: `adx_encode_init`（行 124-139）**
- `nb_channels > 2` チェック → channels ≤ 2 を強制
- `prev[MAX_CHANNELS]`（MAX_CHANNELS=6）に対し ch=0,1 のみアクセス → 安全

**Pass 4: `adx_encode_frame`（行 141-188）**
- フラッシュパス：18バイト確保 → bytestream_put_* で厳密に 18バイト書き込み
- 通常パス：`out_size = 18*channels + (0 or 36)` → 最大72バイト（定数ベース、溢れなし）
- dst への書き込みは `channels * BLOCK_SIZE` = 最大36バイト → 確保サイズと一致

**総合判定**：
- このファイルはエンコーダであり、PCMフレームを受け取って ADX 形式に変換する
- 全てのバッファサイズは定数（BLOCK_SIZE=18、HEADER_SIZE=36、BLOCK_SAMPLES=32）ベース
- channels は init 時に ≤ 2 に制限される
- ループ境界は全て静的定数で確定しており、OOBアクセスは発生しない
- `bufsize` の未使用パラメータは設計上の問題だが、現在の呼び出しパスでは実害なし

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
