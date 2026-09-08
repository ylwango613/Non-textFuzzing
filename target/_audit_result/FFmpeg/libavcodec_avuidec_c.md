全パスを検証しました。最終評価をまとめます。

**分析結果:**

`avui_decode_frame` で確認した潜在的な整数オーバーフローポイント：

1. **Line 62** `opaque_length = 2 * avctx->width * (avctx->height + skip) + 4 * interlaced`  
   → w=32768, h=32752 のとき Python 検算で `2,147,483,652` → int32 で `-2,147,483,644`（符号付きオーバーフロー）

2. **Line 68** `avpkt->size >= opaque_length * 2 + 4`  
   → 上記オーバーフロー後: `opaque_length * 2 + 4` も二重オーバーフローして `12`（t_check_int32=12）  
   → `transparent = 1` が 12バイト以上のパケットで成立してしまう

3. ただし防御チェーンの確認：
   - `av_image_check_size2` の制約 `stride*(h+128) < INT_MAX` はこの次元で **通過**してしまう（~1.1B < 2.147B）
   - しかし 32768×32752 の YUVA422P フレームは **~3GB**（= 32768×32752×3 bytes）
   - `ff_get_buffer(avctx, pic, 0)`（line 71）が 3GB 割り当てを試みて **ENOMEM で失敗**
   - `if ((ret = ff_get_buffer(...)) < 0) return ret;` でその場でリターン
   - 内部ループ（OOB read 発生箇所）には**到達しない**

4. **通常次元（1920×1080 等）**: オーバーフロー一切なし（`opaque_length=4,208,640`、安全）

**結論**: `opaque_length` および `opaque_length*2+4` の整数オーバーフローは理論上存在するが、オーバーフローを引き起こす次元では `ff_get_buffer` が ENOMEM で失敗し、OOB アクセス箇所（内部 k/j ループ）に到達できないため、外部から実際のメモリ安全侵害を引き起こすことは不可能。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
