Now I have a clear picture of the code. Let me verify the exact line-level sequence for both decoders.

**AMR-NB decoder analysis (lines 100–135):**
- Line 103–104: `buf = avpkt->data`, `buf_size = avpkt->size`
- Line 118: `dec_mode = (buf[0] >> 3) & 0x000F;` ← **unconditional access to buf[0]**
- Line 119: `packet_size = block_size[dec_mode] + 1;`
- Lines 121–125: `if (packet_size > buf_size)` ← size validation comes **after** buf[0] is read

If `buf_size == 0`, `avpkt->data` may be NULL or a zero-length allocation; accessing `buf[0]` is undefined behavior / NULL pointer dereference before the guard fires.

**AMR-WB decoder analysis (lines 336–369):**
- Lines 339–340: same pattern: `buf = avpkt->data`, `buf_size = avpkt->size`
- Line 351: `mode = (buf[0] >> 3) & 0x000F;` ← same unconditional access
- Line 354: `if (packet_size > buf_size)` ← guard still too late

## VULN: AMR-NB Decoder buf[0] OOB Read Before Size Check
- **漏洞类别**: memory-safety
- **函数**: amr_nb_decode_frame()
- **行号**: 103-125
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted AMR-NB media file
- **外部触发路径**: ffmpeg -i <crafted.amr> -f null - -> avformat_open_input() -> amrnb demuxer -> avcodec_send_packet() -> amr_nb_decode_frame() -> buf[0] OOB read at line 118
- **描述**: `amr_nb_decode_frame()` 在第 103–104 行将 `avpkt->data` 赋给 `buf`、将 `avpkt->size` 赋给 `buf_size`，随后在第 118 行无条件读取 `buf[0]`（用于提取 mode 字段）。此时并未对 `buf_size >= 1` 进行任何校验；边界检查 `if (packet_size > buf_size)` 在第 121 行才出现，已晚于 `buf[0]` 的访问。当 `buf_size == 0` 时，`avpkt->data` 可为 NULL（FFmpeg 对零长度包的约定）或指向零字节分配，对 `buf[0]` 的解引用属于未定义行为：在 NULL 的情况下直接崩溃（NULL 指针解引用），在非 NULL 的情况下构成越界读（读取分配边界外的堆字节）。
- **触发条件**: 攻击者构造一个含有 size=0 帧的 AMR-NB 文件（或在容器中嵌入 0 字节的 AMR-NB 包），使解复用器向解码器提交 `avpkt->size == 0`、`avpkt->data == NULL` 的包，即可在 `buf[0]` 处触发 NULL 指针解引用或堆 OOB 读。
- **安全影响**: 最坏情况下进程崩溃（DoS）；若 NULL 页可映射或地址布局可控，理论上存在信息泄露可能；在现代 OS（ASLR + NULL 页保护）下主要影响为可重现崩溃。

## VULN: AMR-WB Decoder buf[0] OOB Read Before Size Check
- **漏洞类别**: memory-safety
- **函数**: amr_wb_decode_frame()
- **行号**: 339-358
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted AMR-WB media file
- **外部触发路径**: ffmpeg -i <crafted.awb> -f null - -> avformat_open_input() -> amrwb demuxer -> avcodec_send_packet() -> amr_wb_decode_frame() -> buf[0] OOB read at line 351
- **描述**: `amr_wb_decode_frame()` 在第 339–340 行以相同方式初始化 `buf` 和 `buf_size`，随后在第 351 行无条件执行 `mode = (buf[0] >> 3) & 0x000F;`，而边界校验 `if (packet_size > buf_size)` 直到第 354 行才出现。当 `avpkt->size == 0` 时，`buf[0]` 的访问同样发生在大小验证之前，造成 NULL 指针解引用或越界读。与 AMR-NB 版本相比，此处 `packet_size = block_size[mode]` 不含 `+1`，对于 modes 11/12/13 得到 0，进一步使得 `if (packet_size > buf_size)` 在 buf_size==0 时不触发（0 > 0 为假），仅由第 359 行 `if (!packet_size)` 补救，但此时 `buf[0]` 早已被非法访问。
- **触发条件**: 攻击者构造含有 size=0 帧的 AMR-WB 文件（扩展名 .awb 或封装于 3gp/mp4 中），使解复用器向 AMR-WB 解码器递交 `avpkt->size == 0` 的零字节包，即可在第 351 行触发 NULL 指针解引用或堆越界读。
- **安全影响**: 可重现进程崩溃（DoS）；在特定内存布局下可能泄露相邻堆数据（信息泄露）；在现代系统 NULL 页保护下主要危害为确定性崩溃（拒绝服务）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
