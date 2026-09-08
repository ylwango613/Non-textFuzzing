I now have all the information needed. Let me complete the analysis:

**Core finding in g723_1_parser.c line 41:**
```c
next = frame_size[buf[0] & 3] * FFMAX(1, avctx->ch_layout.nb_channels);
```

- `frame_size[4] = {24, 20, 4, 1}` (uint8_t, max=24)
- No validation of `nb_channels` — contrast with `g729_parser.c` line 53: `if (avctx->ch_layout.nb_channels > 2) s->block_size = 0;`
- Signed integer overflow when `nb_channels` is large

**Verified 3-call exploit chain** (nb_channels = 178956971, valid for any 32-bit channel count container field):
- Call 1, `buf[0]&3=0`: `24 × 178956971 = 4294967304` → wraps to `next=8` (positive) → `pc->buffer` allocated
- Call 2, `buf[0]&3=1`: `20 × 178956971 = 3579139420` → wraps to `next=-715827876` (negative) → `av_assert0` passes (pc->buffer≠NULL) → `pc->overread_index = 0 + (-715827876) = -715827876`; `pc->overread += 715827868`
- Call 3: overread loop executes 715 million times reading `pc->buffer[pc->overread_index++]` = `pc->buffer[-715827876]` → massive OOB read → SIGSEGV

## VULN: Integer Overflow in g723_1 Parser Leading to OOB Memory Access via Corrupted overread_index
- **漏洞类别**: memory-safety
- **函数**: g723_1_parse()
- **行号**: 41
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.9 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file
- **外部触发路径**: `ffmpeg -i <crafted_file> -f null -` → `avformat_find_stream_info()` → `av_parser_parse2()` → `g723_1_parse()` → `ff_combine_frame()` (parser.c:224–225 overread loop) → OOB read
- **描述**: 在 `g723_1_parse()` 第 41 行，`frame_size[buf[0] & 3] * FFMAX(1, avctx->ch_layout.nb_channels)` 是一个无保护的有符号整数乘法。当 `avctx->ch_layout.nb_channels` 很大时（例如 178956971），此乘法发生有符号整数溢出，产生 UB 并在实践中回绕为任意值。由于 G.723.1 支持多种帧类型（`buf[0]&3` 取值 0–3，对应 frame_size 为 24/20/4/1），不同帧类型下相同的 nb_channels 可使 `next` 在一次回绕为小正数（建立 `pc->buffer`）、下一次回绕为大负数（如 -715827876）。第二次调用时 `ff_combine_frame` 的 assert（`next>=0 || pc->buffer`）因 `pc->buffer` 非 NULL 而绕过，随后 `pc->overread_index = pc->index + next = -715827876`、`pc->overread` 被设为 715827876+。第三次调用 `ff_combine_frame` 时，overread 循环 `pc->buffer[pc->index++] = pc->buffer[pc->overread_index++]` 以 `pc->overread_index=-715827876` 为起点执行数亿次迭代，立即越界读取 `pc->buffer` 地址前数百兆字节处的内存，造成内存安全违规。对比：`g729_parser.c` 第 53 行对 `nb_channels>2` 有显式防护，G.723.1 解析器缺少相同防护。
- **触发条件**: 攻击者需构造包含 G.723.1 音频流的媒体文件，其中：①容器头中 channel count 字段为 32 位且设置为可触发溢出的特定大值（例如 178956971）；②音频流中连续帧的首字节低 2 位不同（即连续出现不同帧类型，例如先出现帧类型 0 再出现帧类型 1）。具备 32 位 channel count 字段的容器（如某些 WAV/RIFF、自定义原始封装）可承载该攻击载荷。
- **安全影响**: 可靠触发进程崩溃（SIGSEGV，DoS）。在 32 位地址空间或特殊堆布局下，`pc->overread_index` 指向的负偏移地址若落入已映射内存，可能导致堆内容泄露（信息泄露）；若地址回绕落入可写堆区，理论上可进一步实现受控堆内存破坏（RCE 前提）。最坏情况 DoS，理论上在特定条件下可升级为 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
