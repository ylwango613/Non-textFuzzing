**分析完了。**

**各コードパスの確認結果：**

1. **出力サイズ計算** (`out`): 全コーデックで `out <= 0` チェックあり。ROQ `buf_size - 8`、INTERPLAY `buf_size - 6 - nb_channels`、XAN `buf_size - 2*nb_channels`、SOL `buf_size * 2` いずれも負になれば捕捉。

2. **SOL_DPCM 整数オーバーフロー** (`out = buf_size * 2`): `buf_size > INT_MAX/2` なら符号付きオーバーフローで負値 → `out <= 0` で捕捉。正値の小さい数にラップアラウンドする経路なし。

3. **SOL_DPCM 二重書き込みループ**: `output_samples_u8` を2回インクリメントするが、`out = buf_size * 2` は常に偶数。ループは `out/2` 回で `out` バイトを書き込み、バッファも `out` バイト。OOBなし。

4. **INTERPLAY_DPCM ヘッダ読み取り** (`bytestream2_get_le16u`, unsafe): ステレオで `buf_size=9` の場合、skip後3バイトで4バイト読もうとするが、AVPacket には `AV_INPUT_BUFFER_PADDING_SIZE`（64バイト）のゼロパディングが保証されているため、実際のメモリアクセス違反は発生しない（誤った値を読むが破壊なし）。

5. **配列インデックス**: `s->array[n]` は `uint8_t n`（0-255）, 配列サイズ256。SDX2/CBD2の `s->array[n+128]` は `int8_t n`（-128〜127）、インデックス0〜255。全て合法。

6. **デコードループ内 `bytestream2_get_byteu`**: 全コーデックでループ境界 (`output_samples < samples_end`) と `gb` の残バイト数が一致するよう `out` から計算されている。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
