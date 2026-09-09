The analysis is complete. The comparison between the safe path (line 96–98, which explicitly checks `next >= buf_size`) and the header-completion path (lines 89–94, which has no corresponding check) confirms the bug.

## VULN: sbc_parser heap OOB read in header completion path
- **漏洞类别**: memory-safety
- **函数**: sbc_parse()
- **行号**: 89-94
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted SBC/MSBC audio stream (raw file or container-encapsulated)
- **外部触发路径**: ffmpeg -i <crafted_sbc_file> -f null - -> av_parser_parse2() -> sbc_parse() -> [header_size branch] memcpy(pc->header + pc->header_size, buf, sizeof(pc->header) - pc->header_size) with buf_size < sizeof(pc->header) - pc->header_size
- **描述**: `sbc_parse()` 维护一个 3 字节的 `pc->header[3]` 临时缓冲区，用于跨调用拼凑不完整的 SBC/MSBC 帧头。当第一次调用时 `buf_size < 3` 且帧头无法解析，代码在 line 102 用 `FFMIN(sizeof(pc->header), buf_size)` 保存 `pc->header_size`（例如 1），然后继续到下一次调用。在 line 89–91 的 header-completion 路径中，代码执行 `memcpy(pc->header + pc->header_size, buf, sizeof(pc->header) - pc->header_size)`，即最多从 `buf` 读 `3 - pc->header_size`（最多 2）字节，但**没有检查 `buf_size >= sizeof(pc->header) - pc->header_size`**。若第二次调用时 `buf_size < 2`（例如仍为 1），则此 `memcpy` 读取 2 字节到只有 1 字节合法空间的 `buf`，构成堆越界读（OOB read）。对比之下，正常（非 header_size）路径在 line 96–98 有显式的 `if (next >= buf_size) next = -1` 保护，而 header-completion 路径完全缺失等价检查。最大越界量：2 字节。
- **触发条件**: 攻击者构造一个 SBC/MSBC 音频流，使解析器分两次（每次 1 字节）接收输入：第一次送入以 `0x9C`（SBC_SYNCWORD）或 `0xAD`（MSBC_SYNCWORD）开头的单字节 chunk，使 `sbc_parse_header()` 因 `len < 3` 返回 -1，`pc->header_size` 被设为 1；第二次再送入 1 字节 chunk，触发 line 90-91 的跨越界读取。在 Bluetooth A2DP 流媒体、RTP 传输或自定义 I/O 回调中，小包 / 分片输入是正常场景。
- **安全影响**: 越界读取至多 2 字节的堆相邻内存：若相邻内存存储敏感数据（如密钥、指针），可造成信息泄露；若 `buf` 恰好位于内存页末尾，读取可触发段错误（SIGSEGV），即拒绝服务（DoS）。在 ASAN 下会明确触发 heap-buffer-overflow 报告。直接远程代码执行的可能性极低，因越界量过小（最多 2 字节）且为只读操作。

<!-- AUDIT_PROMPT_VERSION: 1 -->
