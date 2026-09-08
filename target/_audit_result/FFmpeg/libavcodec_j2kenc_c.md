検証が完了しました。整数オーバーフローにより、ヒープバッファのアンダーアロケーションが発生し、後続の書き込みでヒープオーバーフローが起きます。

## VULN: Integer Overflow in Packet Buffer Allocation Leading to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: encode_frame()
- **行号**: 1482
- **CWE**: CWE-190 (Integer Overflow or Wraparound) leading to CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file via transcoding pipeline
- **外部触发路径**: ffmpeg -i crafted.tiff -c:v jpeg2000 output.jp2 -> encode_frame() -> ff_alloc_packet(avctx, pkt, avctx->width\*avctx->height\*9 + FF_INPUT_BUFFER_MIN_SIZE) [integer overflow] -> encode_tile() -> encode_packets() -> encode_packet() -> put_bits()/bytestream_put_buffer() [OOB heap write]
- **描述**: `encode_frame()` の 1482 行目で、パケットバッファサイズを `avctx->width * avctx->height * 9 + FF_INPUT_BUFFER_MIN_SIZE` として計算するが、`avctx->width`・`avctx->height` はいずれも `int` 型であり、この乗算は `int32` 精度で行われる（`int64_t` への拡張は関数呼び出し後の暗黙変換タイミング）。例えば `width=30000, height=16000` の場合、真の値は 4,320,016,384 だが `int32` の折り返しにより `ff_alloc_packet` には `25,049,088`（約 25 MB）が渡される。実際に必要なサイズの約 0.6% しか確保されないまま `s->buf_start` = `pkt->data` に設定されたポインタに対して `put_bits`・`bytestream_put_buffer` がチェックなしでデータを書き続けるため、ヒープバッファの末尾を大幅に超過した連続ヒープ書き込みが発生する。`put_bits`（154〜165 行）自体は `s->buf_end` に対する境界チェックを持たず、`encode_packet` 内の「approximately 20 bytes」チェック（812 行）も不十分であるため、この書き込みはサイレントに継続する。
- **触发条件**: 攻撃者は JPEG2000 以外のフォーマット（TIFF・PNG 等、任意の大きな画像寸法を受け入れるデコーダ経由）で `width=30000, height=16000`（または同様に `int32` の折り返しが小さな正値を生む寸法の組み合わせ）を指定した細工済みメディアファイルを用意し、JPEG2000 エンコーダで再圧縮するトランスコードパイプライン（`ffmpeg -i crafted.tiff -c:v jpeg2000 output.jp2`）を標的に実行させる。ランダムノイズ相当の非圧縮性コンテンツを用いると圧縮効果が低く、エンコード後のデータ量が割り当てバッファを大きく超過しやすい。
- **安全影响**: ヒープバッファの連続的・大規模な書き越しにより、隣接するヒープ管理メタデータおよびその他の確保済みメモリを破壊する。これにより最悪の場合リモートコード実行（RCE）が成立しうる。攻撃者が書き込み範囲とデータ内容を間接的に制御できるため、情報漏洩、任意コード実行、または安定した DoS が想定される影響となる。

<!-- AUDIT_PROMPT_VERSION: 1 -->
