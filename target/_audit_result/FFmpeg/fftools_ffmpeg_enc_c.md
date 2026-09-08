ASS デコーダーの全体経路が確認できました。完全に分析します。

**検証されたデータフロー**:

1. `assdec.c:33-39`: `avctx->subtitle_header = av_malloc(avctx->extradata_size + 1)` → `subtitle_header_size = extradata_size`
2. `ffmpeg_dec.c:1645-1650`: 同パターンを `dp->dec.subtitle_header` にコピー
3. `ffmpeg_enc.c:378-383`: 同パターンを `enc_ctx->subtitle_header` にコピー
4. `assenc.c:35-40` (L407の `avcodec_open2` 経由): 同パターンを `extradata` にコピー

**整数オーバーフロー連鎖の評価**:

- `extradata_size = -1`: `assdec.c:33` で `av_malloc(0)` が glibc 上で非NULLを返し、`assdec.c:37` で `memcpy(ptr, extradata, SIZE_MAX)` → **assdec.c で先にクラッシュ** → ffmpeg_enc.c に到達不能
- `extradata_size = INT_MAX`: `av_malloc(INT_MAX + 1)` が UB で巨大 `size_t` になりメモリ不足 → NULL → ENOMEM 返却 → `subtitle_header = NULL` → `ffmpeg_enc.c:376` の条件不成立
- `subtitle_header_size > 0` (正常範囲): dec.c で `size + 1` バイト確保済み → enc.c での `memcpy(size)` は範囲内で安全

**`do_subtitle_out()` の `local_sub.rects += i` (L515)**:
ASS エンコーダーでは `nb = FFMAX(sub->num_rects, 1)` でループし `local_sub = *sub` を各反復で再初期化。`i` は常に `[0, num_rects-1]` 範囲 → OOB なし。

**`encode_frame()` L770-775**:
`enc->extradata_size` はエンコーダーが生成したもので外部入力ではない → 外部トリガー不可。

**`snprintf` 系 (L142, L916)**:
いずれも `sizeof(dst)` で適切にバウンドされており、スタック溢れなし。

**結論**: `ffmpeg_enc.c` に存在する `subtitle_header_size + 1` パターンはバグパターンとして存在するが、同一条件のクラッシュが `assdec.c:37` で先行して発生し、`ffmpeg_enc.c:381` に独立して到達できる外部トリガー経路は存在しない。他のメモリ安全バグも発見されなかった。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
