ファイル全体（707行）の読み込みと関連ヘッダー・呼び出し元の解析を完了しました。以下の点を詳細に検証しました：

**検証項目**:

1. **`barriers[32]` スタックバッファ境界**: `ff_d3d12va_common_end_frame` で `barriers[32]` に最大 `2 + max_num_ref` エントリが書き込まれる。H264 は `max_num_ref = 17`（2+17=19 ≤ 32）、HEVC は 16（2+16=18 ≤ 32）— 範囲内。

2. **`used_mask` シフトの UB**: `ctx->used_mask |= 1 << i`（i < max_num_ref）。最大 i=16（H264）で `1 << 16` — 符号付き int の UB 範囲外。

3. **`bitstream_size * 1.5` 浮動小数点オーバーフロー**: 理論的に UINT64 の変換 UB が生じるが、実際のフレームサイズは 1.2e19 バイトに達しないため、実際の攻撃ベクタとして機能しない。

4. **`av_calloc` のサイズ計算**: `max_num_ref` は全コーデックでコンパイル時定数由来（≤17）、整数オーバーフロー非発生。

5. **`memset` 範囲**: `ref_subresources` は `max_num_ref * sizeof(UINT)` で確保・クリアされ一致。

6. **エラーパスのメモリリーク** (`reference_only_map` 未解放): `ff_d3d12va_decode_uninit` が cleanup するため安全。

いずれの問題も攻撃者がクラフトしたメディアファイルから外部トリガー可能な記憶安全違反には至らない。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
