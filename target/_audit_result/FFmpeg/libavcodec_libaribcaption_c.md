Now I have a complete picture. Let me analyze the key finding precisely:

**`clut_init()` — Heap OOB Write (lines 278–291):**
- `ctx->clut` is allocated as `AVPALETTE_SIZE` = 1024 bytes = 256 × `uint32_t` (line 1056).
- Inside the loop at line 278, for each character in `region->chars[]`:
  - Line 283: `ctx->clut[ctx->clut_idx++] = rgba;` — **no bounds check**, for unique `text_color`.
  - Line 291: `ctx->clut[ctx->clut_idx++] = rgba;` — **no bounds check**, for unique `back_color`.
  - Lines 299–300: `stroke_color` is the ONLY one that checks `clut_idx < AVPALETTE_COUNT`.
- Initial entries fill indices 0–3. After ~126 chars each with distinct text and back colors, `clut_idx` reaches 256 and subsequent writes go beyond `ctx->clut[255]` — heap OOB write.
- The `char_count` and per-char colors come from the attacker-controlled caption packet via `aribcc_decoder_decode()`.

## VULN: Heap OOB Write in clut_init() via Unbounded CLUT Index
- **漏洞类别**: memory-safety
- **函数**: clut_init()
- **行号**: 278-292
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (ISDB-T/ARIB caption transport stream)
- **外部触发路径**: `ffmpeg -i crafted.ts -f null -` → `aribcaption_decode()` (line 844) → `aribcaption_trans_bitmap_subtitle()` (line 317) → `clut_init()` (line 254) → OOB write at `ctx->clut[ctx->clut_idx++]` (lines 283, 291)
- **描述**: `ctx->clut` 在 `aribcaption_init()` 第 1056 行以 `av_mallocz(AVPALETTE_SIZE)` 分配，大小恰好为 256 个 `uint32_t`（`AVPALETTE_COUNT = 256`）。`clut_init()` 初始化时写入索引 0–3，随后在第 278 行对 `region->char_count` 个字符循环：当字符的 `text_color`（第 283 行）或 `back_color`（第 291 行）与先前颜色不同时，直接执行 `ctx->clut[ctx->clut_idx++] = rgba`，**没有任何 `clut_idx < AVPALETTE_COUNT` 的边界检查**（对比 `stroke_color` 在第 299 行有此检查）。当 `clut_idx` 达到 256 时，写入 `ctx->clut[256]` 及后续地址，越界堆写最多 4 字节，且随字符数增加持续越界，造成堆元数据或相邻对象损坏。
- **触发条件**: 构造含有大量字符（约 127 个以上）且每个字符具有唯一 `text_color` 或 `back_color` 的 ARIB STD-B24 字幕数据包，嵌入 ISDB-T 或 MPEG-TS 容器，以 `-sub_type bitmap` 模式解码（默认 ASS 模式不触发此路径）时即可触发。
- **安全影响**: 可控堆越界写，攻击者可精心布局堆内存以覆盖相邻堆块元数据或对象指针，最坏情况下可实现远程代码执行（RCE）；至少造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
