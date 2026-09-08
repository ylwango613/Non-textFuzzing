**Analysis complete.** Let me summarize findings before writing the final report:

**ts_ring OOB Write/Read (lines 488–490, 555–556):**

- `ts_ring` is declared as `int64_t ts_ring[MAX_REORDER_DELAY * 3 + MAX_ASYNC_DEPTH]` = `int64_t ts_ring[112]`
- Write: `ctx->ts_ring[ctx->input_order % (3 * ctx->output_delay + ctx->async_depth)]`
- `output_delay` = `b_per_p` = `avctx->max_b_frames` — **not bounded by `MAX_REORDER_DELAY=16`**
- When `max_b_frames=17` and `async_depth=64`: divisor = `3×17+64 = 115 > 112`
- `input_order % 115` can produce indices **112, 113, 114** — all OOB into `gop_size`, `closed_gop`, `gop_per_idr`, `p_per_i`, `max_b_depth`, `b_per_p` fields
- Written value (`pic->pts`) can be influenced by input file PTS values
- No `av_assert0` protection on these accesses (confirmed: `av_assert0` is always-enabled, but it's simply absent here)

This is a confirmed OOB write into adjacent struct control fields. The file is an encoder (not a decoder/demuxer), so the trigger is encoder settings (`-bf N` with N > 16), not a crafted input file alone. I'll report with the accurate attack vector.

---

## VULN: ts_ring OOB Write/Read via Unbounded output_delay in HW Encoder
- **漏洞类别**: memory-safety
- **函数**: hw_base_encode_send_frame(), ff_hw_base_encode_set_output_property()
- **行号**: 488-490, 555-556
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted encoder invocation with max_b_frames > 16 (e.g., -bf 17), combined with crafted media file to influence PTS values
- **外部触发路径**: ffmpeg -i <input> -c:v h264_vaapi -bf 17 -async_depth 64 output.mp4 -> ff_hw_base_encode_receive_packet() -> hw_base_encode_send_frame() -> ts_ring OOB write; on output path: ff_hw_base_encode_set_output_property() -> ts_ring OOB read
- **描述**: `FFHWBaseEncodeContext.ts_ring` 数组定义为固定大小 `int64_t ts_ring[MAX_REORDER_DELAY * 3 + MAX_ASYNC_DEPTH]`（即112个元素）。写入索引为 `ctx->input_order % (3 * ctx->output_delay + ctx->async_depth)`，但 `ctx->output_delay`（赋值自 `b_per_p` = `avctx->max_b_frames`）并未被限制在 `MAX_REORDER_DELAY (16)` 以内。当 `max_b_frames = 17`、`async_depth = 64` 时，模除数为 `3×17+64=115 > 112`，导致 `input_order % 115` 可产生 112、113、114 这三个越界下标。越界写入的值为 `pic->pts`（可通过输入文件的 PTS 字段控制），覆盖紧跟 `ts_ring` 之后的结构体字段：`gop_size`、`closed_gop`、`gop_per_idr`、`p_per_i`、`max_b_depth`、`b_per_p`。相同的越界下标计算在 `ff_hw_base_encode_set_output_property()` 的读路径（第555-556行）同样存在，可导致 OOB 读。整个过程中均无 `av_assert0` 或边界检查保护。
- **触发条件**: 使用 VAAPI、D3D12VA 或 Vulkan 硬件编码器，设置 `max_b_frames > MAX_REORDER_DELAY (16)`（如 `-bf 17` 及以上），`async_depth` 使用默认最大值 64。编码超过 113 帧后，`input_order % 115` 将循环命中越界下标 112、113、114，每 115 帧触发一次。攻击者可通过构造含特定 PTS 值的媒体文件影响写入内容。
- **安全影响**: OOB 写入覆盖 `gop_size`、`gop_per_idr`、`max_b_depth` 等编码控制字段，可进一步破坏编码器内部状态，引发二次内存安全违规（如数组越界或空指针解引用）；结合对 `AVFrame *frame`、`AVFifo *encode_fifo`、`AVPacket *tail_pkt` 指针字段的潜在覆写，理论上可导致堆破坏进而实现代码执行（RCE）。在服务端视频转码场景中（`max_b_frames` 由系统配置固定为高值），攻击者通过上传长时长媒体文件即可可靠触发。

<!-- AUDIT_PROMPT_VERSION: 1 -->
