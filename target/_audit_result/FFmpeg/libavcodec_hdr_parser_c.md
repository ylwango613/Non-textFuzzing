完整分析结论：

- `hdr_parser.c` 仅 80 行，逻辑非常简单：在字节流中寻找 `ADIANCE\n`（8字节），找到后令 `next = i - 10` 并调用 `ff_combine_frame`。
- `next` 可为负值（最小 -10），但 `ff_combine_frame`（parser.c:279-288）对负值有专门的 overread 机制处理，不会越界。
- 触发负 `next` 的前提条件是 `ipc->pc.index > 10`（hdr_parser.c:51），保证了 `pc->last_index >= 11`，所以 `pc->buffer[pc->last_index - 8]` 起始位置合法，不存在 OOB。
- `av_fast_realloc` 调用时的 size 参数为 `*buf_size + pc->index + AV_INPUT_BUFFER_PADDING_SIZE`，这三个值均为 `int`，在实际中不会溢出到负值导致欠分配。
- 文件中无 `malloc`/`av_malloc`、无 `memcpy` 直接使用不受信任的大小、无固定栈缓冲区、无整数溢出路径。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
