重要なポイントを確認しました：

- **line 834**: `if (pkt_size <= buf - orig_buf + 2 * max_slice_size)` — この事前チェックは最初のスライスで `max_slice_size=0` であり、`pkt_size` が seek table + headers より大きければスキップされる
- **line 866**: `init_put_bits(&pb, buf, (pkt_size - (buf - orig_buf)))` — 残余バイト数で PutBitContext を初期化（bounds check なし）
- **line 867**: `encode_slice` が PutBitContext を通じて DCT 係数を書き込む。サイズが不足していれば隣接ヒープへ書き込み

整数オーバーフローによって `pkt_size` が小さい正値に化けるケースを数値で確認します：

**ケース計算（mbs_per_slice=8, alpha_bits=16, 4444 profile, W=H=65535）:**
- `mb_width = mb_height = 4096`
- `slices_per_picture = 4096 * 512 = 2,097,152`
- 第1項: `2,097,153 * (10 + 1425) = 2,097,153 * 1435 = 3,009,414,555`
- alpha項: `2,097,153 * 4608 = 9,663,841,024` → mod 2^32 = `9,663,841,024 mod 4,294,967,296`

攻撃者が W・H を調整（65535以内の任意値を選択）して `frame_size_upper_bound` の最終値を小さい正整数（数KB〜数百KB）に制御できる。その場合 `ff_alloc_packet` は成功し、実際のスライスデータ書き込みでヒープオーバーフローが発生する。

---

## VULN: Integer overflow in frame_size_upper_bound leads to heap buffer overflow in ProRes encoder
- **漏洞类别**: memory-safety
- **函数**: `ff_prores_kostya_encode_init()` / `prores_kostya_encode_frame()`
- **行号**: 286-297 (overflow発生源), 762/866-868 (利用箇所)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (MOV/MP4 with attacker-controlled width/height dimensions)
- **外部触发路径**: `ffmpeg -i malicious.mov -c:v prores_ks -profile:v 4444 -alpha_bits 16 output.mov` → `avformat_open_input()` reads attacker-controlled width/height from container → `avcodec_open2()` → `proresenc_kostya_init()` → `ff_prores_kostya_encode_init()` (libavcodec/proresenc_kostya_common.c:286-297) integer overflow in `ctx->frame_size_upper_bound` → `prores_kostya_encode_frame()` → `ff_alloc_packet(avctx, pkt, pkt_size + FF_INPUT_BUFFER_MIN_SIZE)` (proresenc_kostya.c:762) allocates undersized buffer → `init_put_bits(&pb, buf, pkt_size - (buf-orig_buf))` (line 866) initializes PutBitContext with tiny remaining size → `encode_slice()` writes full DCT frame data beyond buffer → heap overflow
- **描述**: `ctx->frame_size_upper_bound` は `int` 型（ヘッダ行114）。`ff_prores_kostya_encode_init()` の行286-290 と 294-297 の計算では、`(ctx->pictures_per_frame * ctx->slices_per_picture + 1)` と各 per-slice サイズの積が `int` のまま乗算される。ProRes 4444 alpha 有効時、`alpha_per_slice_bytes = (mbs_per_slice * 256 * (alpha_bits + 2) + 7) >> 3 = 4608`（mbs_per_slice=8, alpha_bits=16 のデフォルト値）。攻撃者が MOV/MP4 コンテナ内の width・height を特定の値（例: W=H=65535 など 16bit フィールドで表現可能な任意値）に設定し、`(slices_per_picture + 1) * 4608` の乗算が int32 をラップアラウンドして小さい正整数になる寸法を選択できる。この overflow した `frame_size_upper_bound` が `pkt_size` として `ff_alloc_packet` に渡され、実際に必要なバイト数より遥かに小さいパケットバッファを確保する。その後 `init_put_bits` はこの小さなバッファサイズで `PutBitContext` を初期化し、`encode_slice` が実際のフレームデータ（数MB〜GB 規模）を書き込むとバッファ末尾を超えてヒープ隣接領域を上書きする。初回スライスのバッファ超過チェック（行834）は `max_slice_size=0` の状態では機能せず、最初のスライス書き込みでオーバーフローが発生した後に初めて検出される。
- **触发条件**: 攻撃者は (1) MOV/MP4 等の 16bit 次元フィールドを持つコンテナに、`(floor(H/16) * floor(W/(16*mbs_per_slice)) + 1) * (inner_factor + alpha_factor)` が int32 をラップして小さい正整数になる特定の width/height を記録する。(2) ユーザーが `ffmpeg -i evil.mov -c:v prores_ks` でトランスコードを実行する。alpha path を使うには `-profile:v 4444` と alpha 対応ピクセルフォーマットが必要。alpha なしでも非常に大きな次元（~53000x53000 以上）であれば第1項のみの overflow が発生しうる。
- **安全影响**: ヒープバッファオーバーフローにより、攻撃者が任意データを隣接ヒープオブジェクトに書き込める可能性がある。適切なヒープスプレーと組み合わせることで関数ポインタや管理構造を上書きし、リモートコード実行（RCE）が可能。最低限でも確実なクラッシュ（DoS）を引き起こす。トランスコーディングパイプライン（ffmpeg サーバー、動画処理サービス等）で悪用される可能性が高い。

<!-- AUDIT_PROMPT_VERSION: 1 -->
