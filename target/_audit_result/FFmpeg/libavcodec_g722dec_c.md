**分析结论：**

对 `g722dec.c` 的完整审计如下：

**Line 100 — `nb_samples = avpkt->size * 2`**：存在有符号整数溢出的 C UB，但不可利用：若 `avpkt->size` 超过 INT_MAX/2，乘法结果溢出为负数，`ff_get_buffer` 会直接返回错误，循环不会执行。

**Lines 127–129 — `prev_samples[]` 写入**：`prev_samples_pos` 初始化为 22（偶数），每次迭代增量为 2，仅在 `>= 1024` 时通过 memmove 重置回 22。最大写入索引为 1023（pos=1022 时写入 1022 和 1023），数组 `prev_samples[1024]` 始终安全。

**Line 96 — `low_inv_quants[skip]`**：`skip = 8 - bits_per_codeword`，AVOption 强制约束 `bits_per_codeword ∈ [6,8]`，故 `skip ∈ [0,2]`，数组有 3 个元素，安全。

**Line 113–114 — `ihigh`/`ilow` 索引**：`ihigh = get_bits(&gb, 2) ∈ [0,3]`，`ff_g722_high_inv_quant[4]` 安全；`ilow = get_bits(&gb, 6-skip) ∈ [0, 2^(6-skip)-1]`，对应各量化表大小完全匹配。

**`apply_qmf` 指针**：两次写入后 `prev_samples_pos ∈ [24,1024]`，指针偏移 `pos-24 ∈ [0,1000]`，读取 24 个元素最大访问索引 1023，在数组边界内。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
