全ファイル（1640行）を4回に分けて読み込み、関数群ごとに詳細分析を実施した。以下に各分析パスの要約を記録する。

**Pass 1（1-500行）**: 構造体定義、`jpg_init/jpg_decode_block/yuv2rgb`、`epic_hash` 系。`epic_hash_add` は `INT_MAX / sizeof` チェック済み。

**Pass 2（500-999行）**: `epic_decode_tile`の `curr_row[x-1]` でx=0時のアクセスは `c->epic_buf_base + 4` の意図的パディングにより安全。`LOAD_NEIGHBOURS` は y≥2,x≥2 の条件下でのみ呼ばれる。

**Pass 3（999-1202行）**: `kempf_decode_tile`の `uncompress` は `dlen=(tile_width+1)*tile_height` でバッファサイズ以内。`g2m_init_buffers` のタイル次元検証（`tile_width * (uint64_t)tile_height >= INT_MAX/4`）は溢れを防ぐ。

**Pass 4（1202-1640行）**: `g2m_load_cursor` の `cursor_stride` = `FFALIGN(cursor_w, 32/1) * 4`、最大1024×256=262144バイト。割り当て・書き込みサイズ一致。検証で使う `c->cursor_w * c->cursor_h`（旧値）は論理エラーだが初期値0のため初回は第2条件が無効化されるのみ（メモリ破壊なし）。

**潜在事項の検証**:
- `kempf_decode_tile` sub_type=0 で `memcpy(transp, src, 3)` が src_size≥2しか保証されない場合に1-2バイトOOB読み出し → `AV_INPUT_BUFFER_PADDING_SIZE`（64バイト）パディング内への読み出しであり悪用不可
- `jpg_unescape` の `!*src` が `src_end` を1バイト超えて参照 → パディング領域内
- `g2m_decode_frame` でwidth/heightの上限チェック不在 → `ff_set_dimensions` が `av_image_check_size` で弾く
- `kempf_flags`・`framebuf`・`jpeg_tile` の各アクセスはタイル次元検証後に境界内

全てのメモリアクセスパスを追跡した結果、外部から制御可能かつ現実的に利用可能なメモリ安全性脆弱性は検出されなかった。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
