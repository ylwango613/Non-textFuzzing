I have now completed the full analysis. Here are my confirmed findings:

---

**Analysis notes (not part of final report):**

**Vuln 1 (primary):** `fic_decode_frame` line 389 computes `slice_h = FFALIGN(avctx->height - ctx->slice_h*(nslices-1), 16)` — FFALIGN always rounds UP. When `avctx->height % 16 != 0`, this last-slice height extends beyond the actual frame height. `fic_decode_slice` then writes `slice_h` rows unconditionally (loop line 192, `fic_idct_put` writes 8 rows per block). `av_image_alloc` allocates exactly `avctx->height` rows with no extra row-padding. Result: up to 15 extra rows × linesize bytes written past end of frame buffer.

**Vuln 2 (secondary):** `fic_draw_cursor` line 250 computes `dstptr[i] = data[i] + linesize[i]*(cur_y/2) + cur_x/2 + !!i`. The `+!!i` adds +1 byte offset to both chroma plane pointers. When `cur_x/2 + 1 + csize > linesize[1]` (possible when linesize[1] == avctx->width/2 with no alignment slack and cursor is near right edge), `fic_alpha_blend` writes 1 byte past the end of the chroma line. On the last chroma row this goes past the entire plane buffer.

---

## VULN: Heap OOB Write — last slice height rounded past frame buffer in fic_decode_slice
- **漏洞类别**: memory-safety
- **函数**: fic_decode_slice() / fic_decode_frame()
- **行号**: 355-389 (slice_h 计算), 192-201 (OOB 写入循环)
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted FIC media file
- **外部触发路径**: `ffmpeg -i <crafted.fic> -f null -` → `avformat_open_input()` → `av_read_frame()` → `avcodec_send_packet()` → `fic_decode_frame()` (line 355–389, 计算 last slice_h) → `avctx->execute(fic_decode_slice)` (line 410) → `fic_decode_slice()` (line 192–201 写循环) → `fic_decode_block()` → `fic_idct_put()` (line 133–138, 写 8 行像素到帧缓冲区外)
- **描述**: 在 `fic_decode_frame()` 中，最后一个 slice 的高度通过 `FFALIGN(avctx->height - ctx->slice_h * (nslices - 1), 16)`（第 389 行）计算，FFALIGN 向上取整到 16 的倍数。当 `avctx->height` 不是 16 的倍数时（如 height=1000），最后一个 slice 的 slice_h 被上取整为 1008，比实际帧高多出 1~15 行。`fic_decode_slice()` 中写循环 `for (y = 0; y < slice_h; y += 8)` 无额外边界检查，直接调用 `fic_idct_put()` 每次写 8 行像素。而 `ff_reget_buffer()` 通过 `av_image_alloc()` 精确分配 `avctx->height` 行（无额外行填充），因此多出的 1~15 行写操作越过帧缓冲区末端，造成堆溢出。溢出字节数最多为 `15 × linesize` 字节（对 1920 宽视频约 28,800 字节），写入数据为攻击者可控的解码像素值。
- **触发条件**: 攻击者构造一个 FIC 视频文件，其中 `avctx->height` 不是 16 的倍数（例如 height=1000、height=15、height=999 等），packet 携带足量 slice bitstream。无需任何特权，仅需受害者使用 ffmpeg/ffplay 打开该文件即可触发。
- **安全影响**: 攻击者可控数据写入堆缓冲区末端之后，最多约数万字节的堆溢出，可用于覆盖相邻堆元数据或函数指针，在最坏情况下可实现远程代码执行（RCE）；至少造成可靠的进程崩溃（DoS）。

## VULN: 1-Byte Heap OOB Write in fic_draw_cursor Chroma Plane due to Spurious +1 Offset
- **漏洞类别**: memory-safety
- **函数**: fic_draw_cursor()
- **行号**: 248-264
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 5.5 (AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted FIC media file with embedded cursor
- **外部触发路径**: `ffmpeg -i <crafted.fic> -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `fic_decode_frame()` (line 428–434, 判断 cursor 未跳过) → `fic_draw_cursor()` (line 248–250 计算 dstptr) → `fic_alpha_blend()` (line 213–214, 写 1 字节到 chroma 行末端外)
- **描述**: `fic_draw_cursor()` 第 248–250 行对色度平面指针的计算为：`dstptr[i] = data[i] + linesize[i]*(cur_y/2) + cur_x/2 + !!i`。对 i=1（Cb）和 i=2（Cr），`!!i=1` 额外加了 1 字节偏移。当 `cur_x` 接近帧右边缘，且色度平面行宽 `linesize[1]` 恰好等于 `avctx->width/2`（无对齐填充冗余，例如 width=64 配合 32 字节对齐，或 width=128 配合 64 字节对齐）时，`cur_x/2 + 1 + csize` 超过 `linesize[1]`，`fic_alpha_blend()` 写 1 字节到色度行末端之后。若此时 cur_y/2 等于最后一个色度行（`avctx->height/2 - 1`），该写入超过整个色度平面缓冲区末端，造成 1 字节堆越界写。
- **触发条件**: 构造 FIC 文件满足：(1) 光标数据有效（tsize ≥ 32，cursor 尺寸为 32×32，位于帧内）；(2) `avctx->width` 为对齐量两倍的整数倍（如 64、128）使 linesize[1] == avctx->width/2 无余量；(3) 光标 cur_x 设为 `avctx->width - 2`（或接近右边缘），cur_y 设为 `avctx->height - 2` 使色度行在最后一行。
- **安全影响**: 1 字节越界写入可破坏堆分配器元数据或相邻对象，在特定内存布局下可能被利用实现代码执行，通常至少导致程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
