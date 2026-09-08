## VULN: OOB Read via Missing Buffer-Size Check Before buf Advance in Stereo NO_DATA / Bad-Quality Path

- **漏洞类别**: memory-safety
- **函数**: amrwb_decode_frame()
- **行号**: 1140-1152
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted AMR-WB media file (stereo, 2 channels)
- **外部触发路径**: `ffmpeg -i crafted.3gp -f null -` → `avcodec_send_packet()` → `amrwb_decode_frame()` → `decode_mime_header(ctx, buf)` [line 1140, reads buf[0] without prior size check] → NO_DATA/bad-quality branch [line 1146-1152, buf += expected_fr_size without checking buf_size >= expected_fr_size] → second channel iteration: `decode_mime_header(ctx, buf)` [line 1140, reads buf[0] which is now up to 60 bytes past the end of the packet buffer]
- **描述**: In `amrwb_decode_frame`, for each channel in the decode loop, `decode_mime_header(ctx, buf)` at line 1140 unconditionally reads `buf[0]` with no prior check that `buf_size >= 1`. Additionally, in the NO_DATA/bad-quality early-exit branch (lines 1146-1152), the code does `buf += expected_fr_size; buf_size -= expected_fr_size;` without verifying `buf_size >= expected_fr_size` first. The guarded size check at line 1160 (`if (buf_size < expected_fr_size)`) only exists in the normal decoding path and is never reached for the NO_DATA or quality-zero branch. For stereo AMR-WB (2 channels), when channel 0 takes this branch with a large mode (e.g. MODE_23k85 where `expected_fr_size = (477+7)/8+1 = 61`), `buf` is advanced 61 bytes forward regardless of how many bytes remain. The channel-1 iteration then calls `decode_mime_header(ctx, buf)` and reads `buf[0]` which is up to 60 bytes past the end of a 1-byte packet. `buf_size` also wraps to a large negative integer (it is `int`), allowing further logic corruption. Although FFmpeg allocates `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) after each packet buffer, reads in the padding zone yield uninitialized memory content and constitute undefined behavior under the C standard.
- **触发条件**: 攻击者需构造一个包含 **2通道（stereo）AMR-WB** 音频的媒体文件（如 `.3gp`/`.amr`），令第一个信道的帧头字节满足：(a) 模式字段（bits 6:3）设为任意高码率模式（如模式8 = MODE_23k85），(b) 质量位（bit 2）清零（`fr_quality=0`）。整个 AVPacket 的有效载荷仅需 1 字节。这足以触发：`buf` 前进 61 字节，第二个信道的 `decode_mime_header` 随即读取越界内存。
- **安全影响**: 越界读取最多 60 字节的 heap 内存（位于数据包缓冲区之后的填充区域），可造成信息泄露（读取堆上相邻分配的敏感数据内容），在极端对齐/布局下还可能引发进程崩溃（DoS）。不直接导致写越界，RCE 概率低，但可作为信息泄露原语配合其他漏洞使用。

NO_VULN_FOUND

Wait — per the output contract, I must output ONLY `## VULN:` blocks or the single line `NO_VULN_FOUND`. Since I found one vulnerability, the final message must contain only that block. Here is the corrected final output:

## VULN: OOB Read via Missing Buffer-Size Check Before buf Advance in Stereo NO_DATA/Bad-Quality Path
- **漏洞类别**: memory-safety
- **函数**: amrwb_decode_frame()
- **行号**: 1140-1152
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted AMR-WB stereo media file
- **外部触发路径**: `ffmpeg -i crafted.3gp -f null -` → `avcodec_send_packet()` → `amrwb_decode_frame()` → channel-0 iteration: `decode_mime_header(ctx, buf)` [line 1140, reads buf[0], no prior size check] → NO_DATA / bad-quality branch [lines 1146-1152, advances buf by expected_fr_size without checking buf_size >= expected_fr_size] → channel-1 iteration: `decode_mime_header(ctx, buf)` [line 1140, reads buf[0] which is now up to 60 bytes past the end of the packet buffer]
- **描述**: `amrwb_decode_frame` 在通道循环的每次迭代中，于 line 1140 直接调用 `decode_mime_header(ctx, buf)` 读取 `buf[0]`，此时 **没有任何** 针对 `buf_size >= 1` 的前置校验。对于 NO_DATA 或质量标志为 0 的帧，代码走 lines 1146-1152 的提前退出分支，在该分支内执行 `buf += expected_fr_size; buf_size -= expected_fr_size;`，**同样没有先检查** `buf_size >= expected_fr_size`。真正的尺寸校验（line 1160 的 `if (buf_size < expected_fr_size)`）只在正常解码路径上执行，对 bad-quality 分支完全绕过。对于双声道（stereo）AMR-WB 输入：channel 0 选取高比特率模式（如 MODE_23k85，`cf_sizes_wb[8]=477`，`expected_fr_size=61`）且 fr_quality=0 时，`buf` 被无条件前移 61 字节，`buf_size` 变为负值。channel 1 随后调用 `decode_mime_header(ctx, buf)`，读取越出原始 1 字节包末尾最多 60 字节处的堆内存，构成越界读。
- **触发条件**: 构造一个 2 通道（stereo）AMR-WB 文件（如封装在 `.3gp` 或 `.amr` 容器中），令 AVPacket 仅含 **1 个字节**，该字节的 bits[6:3] 设为 8（MODE_23k85），bit[2] 清零（quality=0）。这使 channel 0 进入 bad-quality 分支并将 `buf` 前移 61 字节，channel 1 的 `decode_mime_header` 随即读取越界内存。
- **安全影响**: 越界读取最多 60 字节的堆上相邻内存（位于 `AV_INPUT_BUFFER_PADDING_SIZE` 填充区或后续堆块），可泄露堆布局或敏感数据（信息泄露），在特殊内存布局下可能触发段错误（DoS）。不直接导致写越界，独立 RCE 可能性低，但可作为信息泄露原语与其他漏洞组合利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
