I have now fully traced the vulnerability. Here is my final report:

## VULN: Stack Buffer Overflow via Inflated dsize in decodeMP3 (Layer 3 part2_3_length)
- **漏洞类别**: memory-safety
- **函数**: decodeMP3()
- **行号**: 614-618
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP3 file
- **外部触发路径**: mp3gain main() [mp3gain.c:2262] → decodeMP3(&mp, curframe, bytesinframe, &nprocsamp) [interface.c:618] → copy_mp(mp, mp->dsize, wordpointer)
- **描述**: 在 `decodeMP3()` 处理 MPEG1 Layer 3 帧的 data_parsed 阶段，`mp->dsize = (bits+7)/8` 由 `do_layer3_sideinfo()` 返回值（`databits - 8*main_data_begin`，line 588）推算而来。`databits` 等于所有 granule×channel 的 `part2_3_length` 字段之和，该字段为 12-bit 文件字段，最大值 4095。对 MPEG1 立体声（2 granule × 2 channel）：`databits_max = 4 × 4095 = 16380`，`main_data_begin=0` 时 `dsize_max = (16380+7)/8 = 2048`。line 618 执行 `copy_mp(mp, 2048, wordpointer)`，其中 `wordpointer = mp->bsspace[mp->bsnum] + 512 + mp->ssize`（约 +544）。`bsspace[bsnum]` 定义为 `unsigned char bsspace[2][MAXFRAMESIZE+512]`（MAXFRAMESIZE=1792），每个子数组仅 2304 字节，从偏移 544 处仅剩 1760 字节可用，而 `copy_mp` 不做任何大小检查，直接 `memcpy` 2048 字节，越界写入约 288 字节。`copy_mp` 内无任何边界检查（interface.c:175-196 纯 memcpy 循环）。`MPSTR mp` 在 `main()` 中以栈变量形式声明（mp3gain.c:1413），故溢出损坏紧随 bsspace 的 `real hybrid_block[2][2][576]` 等 MPSTR 成员。
- **触发条件**: 构造一个 MPEG1 Layer 3 立体声 MP3 帧：sync word 合法（0xFFE），bitrate_index != 0xF，sampling_frequency_index != 0x3，side info 中 `main_data_begin=0`，`part2_3_length[gr][ch]=4095`（所有 4 个字段），并在帧数据区提供 ≥2048 字节，使 `mp->bsize >= 2048`（绕过 line 614 的 bsize 检查）。攻击者完全控制溢出的 288 字节内容（来自 MP3 数据区）。
- **安全影响**: 攻击者控制内容的栈内越界写，可破坏 `MPSTR.hybrid_block`，进一步影响后续 III_hybrid() 的浮点计算；精心构造时可能借助 MPSTR 内后续控制字段（如 `bsnum`、`synth_buffs`、`sync_bitstream`）实现二次内存破坏，最坏情况下可达 RCE（若后续使用损坏的控制数据作为索引/指针），或确定性 DoS（进程崩溃）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
