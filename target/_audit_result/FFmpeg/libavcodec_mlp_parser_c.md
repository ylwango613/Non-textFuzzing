全体的な分析が完了しました。最終的な脆弱性レポートを出力します。

## VULN: Heap OOB Read in mlp_parse() Parity Check Loop via Unbounded Buffer Access
- **漏洞类别**: memory-safety
- **函数**: mlp_parse()
- **行号**: 146-154
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MLP/TrueHD media file
- **外部触发路径**: ffmpeg -i <crafted.truehd> -f null - → av_parser_parse2() → mlp_parse() → parity check loop at mlp_parser.c:146-154
- **描述**: `mlp_parse()` 中的奇偶校验循环（第 146–154 行）使用指针变量 `p` 逐字节访问 `buf[]`，但在整个循环体内对 `p` 没有任何上界检查（无 `p < buf_size` 保护）。循环迭代次数为 `mp->num_substreams + 1`（包含 i=-1 的额外一次），其中 `mp->num_substreams` 来自上一个同步帧的 4-bit 字段，取值范围 0–15（`ff_mlp_read_major_sync` 第 160 行：`mh->num_substreams = get_bits(gb, 4)`），而 `MAX_SUBSTREAMS=4` 的常量并不对该字段做截断校验。每次迭代至少读 2 字节，当 `i < 0`（i=-1 迭代固定满足）或 `buf[p-2] & 0x80` 时再追加读 2 字节。最坏情况下（num_substreams=15 且所有子流头最高位置 1），循环共读取 4×16 = 64 字节。若后续非同步帧（buf_size 可小至 2 字节，由 `(header_bits & 0xfff) * 2` 控制）完整到达且 `pc->index==0`（无缓存，ff_combine_frame 不切换 buf 到带填充的 pc->buffer），则 `buf` 仍指向调用者原始缓冲区，循环越界读取最多 `4*(num_substreams+1) - buf_size` 个字节（最坏 62 字节）。这些字节处于帧边界之外的堆内存，可能属于相邻 chunk 元数据。即使在标准 FFmpeg 调用路径中 AVPacket 携带 64 字节零填充，越界读也会被 AddressSanitizer 的 red-zone 检测到；在非标准调用路径（直接调用解析 API 且无填充保证）中则会导致真实的堆越界读取。
- **触发条件**: 攻击者构造一个 TrueHD/MLP 码流，其中：① 第一帧为合法同步帧，但在 `num_substreams` 字段（4 位）写入 15（远超实际 MAX_SUBSTREAMS=4）；② 紧随其后发送一个极短的非同步帧（帧长字段设为最小合法值，如 buf_size=8），该帧没有同步标志（`AV_RB32(buf+4) & 0xfffffffe != 0xf8726fba`）；③ 此时 `mp->num_substreams` 仍保持为 15，而实际数据仅 8 字节，奇偶校验循环尝试访问 buf[0]..buf[63]，越界读取 56 字节。
- **安全影响**: 最坏情况下读取帧缓冲区之后最多 ~62 字节的堆内存。在无填充路径下可能造成进程崩溃（DoS）；在有相邻堆数据的场景下可能泄漏敏感信息（如其他解码上下文的内存内容）。该漏洞不直接导致写操作，纯粹为读越界，单独利用难以实现 RCE，但可作为信息泄漏原语与其他漏洞配合使用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
