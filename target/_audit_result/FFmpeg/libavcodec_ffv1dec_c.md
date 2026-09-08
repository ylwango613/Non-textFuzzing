The vulnerability is confirmed. In release builds `av_assert2` is a no-op (only active at ASSERT_LEVEL > 1), so the bounds check at line 77 of the template is silently skipped. The state allocation at ffv1.c:82 is exactly `p->context_count * 32` bytes, but `context` can exceed `p->context_count` with crafted quant_tables.

## VULN: Heap OOB Read/Write via Crafted Quant-Table Context Index in FFV1 Decoder
- **漏洞类别**: memory-safety
- **函数**: `RENAME(decode_line)()` (实例化为 `decode_line` / `decode_line32`)
- **行号**: ffv1dec_template.c:77-80 (引用 ffv1.c:82-88 的分配 + ffv1_parse.c 中的 read_quant_table)
- **CWE**: CWE-787 (Out-of-bounds Write) / CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted FFV1 media file (mkv/avi/raw)
- **外部触发路径**: `ffmpeg -i <crafted_file> -f null -` → `avformat_open_input()` → `avcodec_open2()` → `decode_init()` → `ff_ffv1_read_extra_header()` → `ff_ffv1_read_quant_tables()` / `read_quant_table()` → [sets up malicious quant_tables with all ret=1, resulting in `p->context_count=1`] → `decode_frame()` → `decode_slices()` → `decode_slice()` → `ff_ffv1_init_slice_state()` [allocates `p->state = av_calloc(1, 32)`] → `decode_plane()` → `decode_line()` → `get_context()` [returns abs value up to 5] → `p->state[context]` OOB at ffv1dec_template.c:80
- **描述**: `decode_line`（通过 `ffv1dec_template.c` 展开）在访问 `p->state[context]` 或 `p->vlc_state[context]` 之前，仅用 `av_assert2(context < p->context_count)`（第77行）进行边界检查。`av_assert2` 在 ASSERT_LEVEL ≤ 1（默认发行版构建）时被预处理为 `((void)0)`，即空操作，运行时不做任何检查。`context` 由 `get_context()` 计算：对 5 张量化表各做一次查找后求和取绝对值，最大可达 `5 × max_per_table`。而 `p->context_count` 由 `ff_ffv1_read_quant_tables()` 决定，当攻击者令所有 5 张表的 `ret=1`（每张表中所有条目映射至 v=0 或 v=1，即 `2×1−1=1`）时，最终 `context_count_total = 1^5 = 1`，返回值 `(1+1)/2 = 1`，故 `p->context_count = 1`。`p->state` 仅分配 `1 × 32 = 32` 字节，而 `context` 最大为 5，导致 `p->state[5]` 访问越界 160 字节之外的堆内存。`get_symbol_inline()` 在该越界地址上执行范围编码器的概率状态读取与**写入**（`*state = c->one_state[*state]`），构成堆外写漏洞。在 AC_GOLOMB_RICE 模式下，`p->vlc_state[context]` 同样越界（每个 `VlcState` 结构 8 字节）。
- **触发条件**: 攻击者构造含恶意 extradata 的 FFV1 关键帧（可嵌入 MKV/AVI/原始 FFV1 容器）：在 extradata 的量化表段中，令 5 张量化表各自仅使用 `v=0`（1个条目）和 `v=1`（127个条目），使每张表 `ret=1`；解码时输入像素差值任意（攻击者无需控制帧数据内容即可触发，因为大量像素差值会命中 `v=1` 的条目，使 `context` 达到 ≥ 1 从而越界）。
- **安全影响**: 堆越界写（Heap OOB Write），攻击者通过控制量化表布局影响越界写的内容（range coder 将 `c->one_state[*oob_byte]` 写回 `*oob_byte`），可覆盖相邻堆元数据或对象指针，在最坏情况下可实现**远程代码执行（RCE）**；同时存在堆越界读，可导致敏感内存信息泄漏。

<!-- AUDIT_PROMPT_VERSION: 1 -->
