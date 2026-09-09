Now I have complete information. Let me trace the exact byte-level discrepancy for the key widths.

**Analysis of the size check vs actual bytes consumed by the loop:**

- `width % 6 == 2` (e.g., width=2, 8, 14…): actual bytes/row = `⌈width*8/3⌉` aligned to 8 = `width*8/3 + 3`; formula gives `width*8/3` (floor). **Gap: 3 bytes per row.**
- `width % 6 == 4` (e.g., width=4, 10, 16…): actual = `width*8/3 + 2`; formula gives floor. **Gap: 2 bytes per row.**
- `AV_INPUT_BUFFER_PADDING_SIZE` = 64 bytes, so for height ≥ 22 (width=2) the OOB read escapes into adjacent heap memory.

The loop reads 4 `uint32_t` values (16 bytes) per 6 Y-pixels. With width=2, per-row the loop reads 2×4 = 8 bytes, but the size guard allows only `⌊2×8/3⌋ = 5` bytes. `decode_init` only rejects odd widths; width=2 is accepted.

## VULN: Heap OOB Read via Integer Truncation in Packet Size Check (v210x decoder)
- **漏洞类别**: memory-safety
- **函数**: decode_frame()
- **行号**: 48-113
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted media file (MOV/QuickTime or AVI container with a v210x video track)
- **外部触发路径**: `ffmpeg -i crafted.mov -f null -` → `avformat_open_input()` → MOV demuxer sets `avctx->width=2` (or any 6k+2 / 6k+4 even value) → `avcodec_decode_video2()` / `avcodec_send_packet()` → `decode_frame()` → OOB read from `avpkt->data`
- **描述**: `decode_frame()` 在第48行使用整数除法 `avctx->width * avctx->height * 8 / 3` 来校验包大小下界。该公式因 C 整数截断（floor division）而系统性地低估了实际需要读取的字节数。v210x 格式每6个 Y 采样消耗4个 uint32_t（16字节），但当 `width % 6 == 2` 时，每行实际需要 `(width*8/3 + 3)` 字节，公式仅要求 `width*8/3` 字节（差3字节/行）；当 `width % 6 == 4` 时差2字节/行。`decode_init()` 仅拒绝奇数宽度（`width & 1`），宽度为2、4、8、10等的帧被正常接受。当攻击者提供恰好等于 `floor(width*height*8/3)` 字节的包时，解码循环的 `src++` 指针将读取超出 `avpkt->data + avpkt->size` 的堆内存。当 `height ≥ 22`（width=2）时，超读量（`3*height` 字节）超过 FFmpeg 的64字节 `AV_INPUT_BUFFER_PADDING_SIZE` 填充，进入相邻堆内存区域。
- **触发条件**: 攻击者构造一个 MOV/QuickTime（或 AVI）文件，其中 v210x 视频轨道的宽度设为2（或满足 `width % 6 == 2` 或 `width % 6 == 4` 的任意偶数），高度设为 ≥ 22，并将视频帧数据包的实际大小设为恰好等于 `floor(width * height * 8 / 3)` 字节。例如：width=2, height=1080，包大小=5400字节，而解码器实际读取8640字节，超读3240字节。
- **安全影响**: 解码器从 `avpkt->data` 缓冲区之外读取最多 `height * 3` 字节的堆内存（对于1080行的帧达3240字节），可泄露相邻 AVPacket 数据、堆元数据或敏感内容（信息泄露）。在某些堆布局下，若超读区域跨越未映射页面，可导致进程崩溃（DoS）。作为信息泄露原语，在多次请求场景（如服务端媒体转码）中可用于绕过 ASLR 辅助后续 RCE 利用链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
