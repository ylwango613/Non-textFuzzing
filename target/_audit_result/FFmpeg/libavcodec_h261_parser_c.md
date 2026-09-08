I've completed the full analysis of `h261_parser.c` (96 lines) and traced its call into `ff_combine_frame` in `parser.c`. Here is my finding:

**Root cause trace:**

In `h261_find_frame_end` (line 56), the second scan loop returns `i - 2`. The second loop starts at a minimum of `i = 1` (when the first start code was found at `buf[0]`, causing the outer loop to post-increment `i` to 1 before exiting). If the second start code is immediately matched at `i = 1`, the function returns `1 - 2 = -1`. This negative `next` value is passed to `ff_combine_frame`.

In `ff_combine_frame` (parser.c lines 234, 256-286): after a complete frame has been assembled in a prior call, `pc->index` is reset to 0 (line 275) but `pc->buffer` remains allocated. On the subsequent call with `next = -1`:
- `pc->last_index = pc->index = 0` (line 234)
- `*buf_size = pc->overread_index = 0 + (-1) = -1` (line 256–257)
- The `if (pc->index)` branch (line 260) is skipped
- The overread loop (line 284) executes once: accesses `pc->buffer[pc->last_index + next]` = `pc->buffer[0 - 1]` = **`pc->buffer[-1]`** — a 1-byte heap OOB read before the allocated buffer

Additionally, `*poutbuf_size = -1` is returned to the H.261 decoder, which may misinterpret it as a large unsigned size in downstream codec paths.

## VULN: h261_find_frame_end returns i-2 causing 1-byte heap OOB read in ff_combine_frame
- **漏洞类别**: memory-safety
- **函数**: h261_find_frame_end() / ff_combine_frame()
- **行号**: 56 (h261_parser.c) → parser.c:284-287
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted H.261 media file
- **外部触发路径**: `ffmpeg -i <crafted.h261> -f null -` → `avcodec_parser_parse2()` → `h261_parse()` → `h261_find_frame_end()` returns -1 → `ff_combine_frame(pc, -1, ...)` → `pc->buffer[pc->last_index + next]` = `pc->buffer[-1]` OOB read
- **描述**: 在 `h261_find_frame_end` 的第二段扫描循环（parser.c line 50–59）中，当 `vop_found` 在 `buf[0]` 处被设置后，外层 for 循环对 `i` 执行后置自增，使 `i = 1` 进入第二段循环。若第二段循环在 `i = 1` 处立刻再次命中 start code 模式，则 `return i - 2 = -1`。该 `-1` 作为 `next` 传入 `ff_combine_frame`：在 `pc->index = 0`（前一帧组装完毕后重置）但 `pc->buffer != NULL`（缓冲区未释放）的状态下，`pc->last_index` 被赋为 0，`if (pc->index)` 分支被跳过，overread 循环执行 `pc->buffer[0 + (-1)] = pc->buffer[-1]`，越界读取堆块起始位置前一字节（通常为堆元数据或相邻分配块内容）。
- **触发条件**: 攻击者构造一个畸形 H.261 比特流文件：首先传输足够多的数据使 `pc->buffer` 被分配、`pc->index` 被重置为 0（即完成一帧组装后进入下一帧）；随后在新的 packet 中，`pc->state` 残留字节与 `buf[0]` 组合命中 start code 位模式（`(state >> j) & 0xFFFFF0 == 0x000100`），且 `buf[1]` 同样命中第二个 start code，迫使 `h261_find_frame_end` 返回 `1 - 2 = -1`。
- **安全影响**: 从堆缓冲区起始地址前一字节读取任意内容（信息泄露，可能暴露堆布局元数据），同时 `*poutbuf_size` 被设置为 -1 并传递给下游 H.261 解码器，若解码器将其强转为无符号整数（如用于后续 memcpy 长度），可导致进一步的内存越界操作或进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
