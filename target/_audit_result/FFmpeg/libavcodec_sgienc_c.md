I now have all the data needed for a definitive conclusion. Let me trace the arithmetic precisely one final time to confirm the heap overflow.

**Concrete proof of trigger** (AV_PIX_FMT_RGBA, width = 8189, height = 65535, `s->rle = 1` / default):

- `depth = 4` (SGI_RGBA), `bytes_per_channel = 1`
- `tablesize = 4 × 65535 × 4 = 1,048,560` (correct, no overflow here)
- `depth × height × (2×width+1)` in `unsigned int`: `262140 × 16379 = 4,293,591,060` (fits in uint32)
- `tablesize×2 + 4,293,591,060` = `2,097,120 + 4,293,591,060 = 4,295,688,180` → **overflows uint32** → wraps to `720,884`
- `length = 512 + 720,884 = 721,396`; `ff_alloc_packet(…, 721,396)` succeeds → heap buffer of **721,396 bytes**

After the 512-byte header, only **720,884 bytes** remain in `pbc`. `bytestream2_skip_p(&pbc, tablesize=1,048,560)` clips to 720,884 and sets `pbc.eof=1`.

`taboff_pcb` is then initialised with `buf = pkt->data+512`, `buf_size = tablesize = 1,048,560` → **`buffer_end = pkt->data + 1,049,072`**, which is **327,676 bytes past the end of the real allocation**. Subsequent `bytestream2_put_be32(&taboff_pcb, …)` calls check only `taboff_pcb.buffer_end − buffer ≥ 4` (not the actual heap limit), so from write #180,222 onward every 4-byte write goes out-of-bounds.

`tablen_pcb` is initialised with `buf = pbc.buffer = pkt->data + 721,396` (= end of allocation), `buf_size = tablesize = 1,048,560` → **all 262,140 × 4-byte writes are fully out-of-bounds**, overwriting ~1 MB of adjacent heap memory.

Total heap corruption: up to ≈1.376 MB past the 721,396-byte buffer; the written values are deterministic (table offsets and lengths), making controlled heap layout attacks plausible.

---

## VULN: Integer Overflow in RLE Length Calculation Leads to Heap Buffer Overflow in SGI Encoder
- **漏洞类别**: memory-safety
- **函数**: encode_frame()
- **行号**: 156-234
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: `ffmpeg -i crafted.mp4 -vcodec sgi output.sgi` → `avcodec_encode_video2()` → `ff_encode_get_frame()` → `encode_frame()` (sgienc.c) → `bytestream2_put_be32(&taboff_pcb/&tablen_pcb, …)` writes out-of-bounds
- **描述**: 在 `encode_frame()` 的 RLE 分支中（行 161），`length` 的计算为 `length += tablesize * 2 + depth * height * (2 * width + 1)`。所有操作数均为 `unsigned int`，当 `depth×height×(2×width+1)` 接近 2³² 时，该表达式会发生 uint32 整数溢出并回绕为很小的正值，再加上 `tablesize×2` 后可能再次溢出，最终导致 `length` 远小于所需空间。`ff_alloc_packet` 因此只分配很小的缓冲区（例如 width=8189, height=65535, RGBA 时仅分配 721,396 字节，而实际所需 `512 + 2×tablesize = 1,049,072` 字节）。随后代码在第 196 行用 `tablesize` 作为 `buf_size` 初始化 `taboff_pcb`、第 200 行初始化 `tablen_pcb`，但这两个子上下文的 `buffer_end` 分别指向真实堆分配结束之后的位置。由于 `bytestream2_put_be32` 仅依赖子上下文自身的 `buffer_end` 做边界检查，所以 `taboff_pcb` 的后续写入（第 211 行）以及 `tablen_pcb` 的全部写入（第 231 行）均发生堆越界写入，造成 heap buffer overflow。
- **触发条件**: 攻击者提供一个宽度约为 8189（或满足特定模 2³² 余数的其他值，范围 1–65535）、高度约为 65535 的视频文件（MP4/MKV 等任意格式），要求目标以默认 RLE 模式（`rle=1`，默认值）将其编码为 SGI 格式；像素格式可为 AV_PIX_FMT_RGBA（8 位，最易触发）、AV_PIX_FMT_RGBA64LE/BE 或 AV_PIX_FMT_RGB48* 等均可触发。不需要任何特殊编译选项。
- **安全影响**: 堆越界写入最多约 1.4 MB 的连续内存区域，写入内容为可预测的 RLE 偏移量和长度值，可覆盖紧邻的堆块元数据或对象，最坏情况下可导致远程代码执行（RCE）；在典型服务端 FFmpeg 转码场景（视频转换服务/CDN）中攻击者无需本地访问权限即可触发，最小化条件下至少造成可靠崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
