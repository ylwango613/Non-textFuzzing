All types are confirmed. The analysis is complete.

**Summary of finding:** At line 42, `4 * avctx->height * aligned_width` is a pure `int` multiplication. When width ≈ height ≈ 23171, the product exceeds `INT_MAX` (2,147,483,647), wraps to a large negative number, and the size check `avpkt->size < <negative>` is always false for any non-negative `avpkt->size`. This bypasses the only guard, and the inner loop at lines 56-59 reads `src[4*j]`…`src[4*j+3]` far beyond the end of the packet buffer.

---

## VULN: Integer Overflow in Size Check Leads to OOB Read in y216_decode_frame
- **漏洞类别**: memory-safety
- **函数**: y216_decode_frame()
- **行号**: 39-66
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (AVI/MKV/MP4 with TARGA_Y216 codec)
- **外部触发路径**: `ffmpeg -i crafted.avi -f null -` → `avformat_open_input()` → demuxer sets `avctx->width`/`avctx->height` from container header → `avcodec_send_packet()` → `y216_decode_frame()` → integer overflow at line 42 → OOB read at lines 56-59
- **描述**: 在 `y216_decode_frame()` 的第 39 行，`aligned_width` 被声明为 `int`，其值为 `FFALIGN(avctx->width, 4)`（纯 `int` 运算）。第 42 行的边界检查 `if (avpkt->size < 4 * avctx->height * aligned_width)` 全程使用有符号 32 位整数运算。当 width ≈ height ≈ 23171 时（`aligned_width = 23172`），乘积 `4 × 23171 × 23172 ≈ 2,147,673,648` 超过 `INT_MAX`（2,147,483,647），发生有符号整数溢出，结果回绕为约 `-2,147,293,649`。此时比较变为 `avpkt->size < -2,147,293,649`，对任何非负的 `avpkt->size` 均为假，导致尺寸检查被完全绕过。随后内层循环（第 55-60 行）对 `src`（指向 `avpkt->data` 的 `uint16_t *`）连续读取 `src[4*j]`、`src[4*j+1]`、`src[4*j+2]`、`src[4*j+3]`（j 最大达 `width/2 - 1`），再加上每行结束后 `src += aligned_width << 1` 的行偏移累积，总计尝试读取约 2 GB 数据，而实际数据包可能仅有数百字节，造成大范围堆越界读取。
- **触发条件**: 攻击者构造一个包含 TARGA_Y216（`AV_CODEC_ID_TARGA_Y216`）视频流的畸形媒体文件（如 AVI），在容器头中将 width 和 height 均设置为约 23171（或其他使 `4 × height × aligned_width > INT_MAX` 的值），同时使视频数据包的实际载荷远小于真正需要的字节数（例如仅 1 KB）。
- **安全影响**: 大范围堆越界读取，可能泄露解码器进程堆内存中的敏感数据（密钥、用户数据、其他帧内容等）；若读取跨越未映射内存页，则导致进程崩溃（DoS）。在有精确堆布局控制的情景下，可用于信息泄露辅助进一步利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
