逐一分析关键路径：宽高来源、索引 sum 计算、主循环中所有 memcpy/memset 边界。

**分析摘要**

1. **width/height 来源**（mspdec.c:64-65）：`avio_rl16` 读取，最大值 65535。`2 * height ≤ 131070`，在 `int` 范围内无溢出；`(width + 7) / 8` 同样无溢出。

2. **demuxer 内 `size` 累加**（mspdec.c:97-99）：最坏情况 `65535 × 65535 = 4,294,836,225 < UINT_MAX`，无溢出，正常。

3. **`buf_size` 符号比较**（msp2dec.c:60）：`pkt_size`（unsigned）vs `buf_size`（int）。初始 `buf_size > 2*height ≥ 0`，循环内始终通过 clip 保持 ≥ 0，unsigned 提升不会混淆比较。

4. **memcpy 边界**（msp2dec.c:71）：`FFMIN(size, width - x)`，循环守卫 `x < width` 确保 `width - x ≥ 1`；`size` 已被 bytestream2 截断至剩余字节数，双重保护。

5. **memset 边界**（msp2dec.c:56, 79）：目标 offset = `y * linesize[0] + x`，均在 `ff_get_buffer` 分配范围内；length = `FFMIN(size, width - x)` 有界。

6. **bytestream2 init**（bytestream.h:141）：`av_assert0(buf_size >= 0)` 在调试/发布均有效防护；buf_size 最大为 `2 * height ≤ 131070`，正常。

7. **逃逸 size==0 的无进展分支**（msp2dec.c:75-80）：每次最少消耗 2 字节（run-length + value），bytestream2 最终耗尽，不构成无限循环或内存写越界。

整个文件使用 bytestream2 API 进行安全读取，所有 memcpy/memset 均经过 `FFMIN` 双重裁剪，width/height 受 u16 自然上限约束，未发现可外部触发的内存安全漏洞。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
