I now have the full picture. Let me trace the critical code paths:

**Key findings from analysis:**

**Batch 1 (lines 1-350):** `PredictorSetup()` checks `td_bitspersample ∈ {8,16,32}` for `PREDICTOR_HORIZONTAL`, but for `PREDICTOR_FLOATINGPOINT` (predictor=3) it **only** checks `td_sampleformat == SAMPLEFORMAT_IEEEFP` — no `td_bitspersample` validation. `fpAcc` and `fpDiff` both compute `bps = td_bitspersample / 8` (uint32 integer division).

**Batch 2 (lines 351-548):** In `fpAcc`, `cc` bytes are allocated for `tmp`, but the first accumulation loop `while (count > stride)` runs `REPEAT4(stride, ...)` unconditionally `stride` times per iteration. If `cc % stride != 0`, the last REPEAT4 accesses up to index `cp_start + 2*stride - 1`, which exceeds `cc - 1`.

**Critical path:** With `td_bitspersample = 9` (non-standard but library-accepted), `bps = 1` (no division by zero), `TIFFhowmany8(9 × tilewidth × stride)` rounds up and produces a `rowsize` that is **not** a multiple of `stride`. This makes `cc % stride ≠ 0`. Verification with cc=17, stride=5 shows writes to cp0[17], cp0[18], cp0[19] (3 bytes past end). With larger stride (e.g., 65535) the overflow reaches 57 KB.

In `fpDiff`, the backwards REPEAT4 loop reads `cp0[-1]`, `cp0[-2]`, etc. (below the buffer start).

**Type confirmation:** `tsize_t` = `int32` (signed). `bps` = `uint32`. `stride` = `int`. `rowsize` = `tsize_t`.

## VULN: Heap Buffer Overflow in fpAcc via Non-Multiple-of-8 BitsPerSample with Floating-Point Predictor
- **漏洞类别**: memory-safety
- **函数**: fpAcc()
- **行号**: 352-383
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadDirectory() → PredictorSetupDecode() → [tile/strip decode] → PredictorDecodeTile() / PredictorDecodeRow() → fpAcc()
- **描述**: `fpAcc()` 用于 PREDICTOR_FLOATINGPOINT (predictor=3) 的解码路径。`PredictorSetup()` 对 predictor=3 仅检查 `td_sampleformat == SAMPLEFORMAT_IEEEFP`，不检查 `td_bitspersample`。`fpAcc` 计算 `bps = td_bitspersample / 8`（整数除法），当攻击者将 `td_bitspersample` 设为非 8 的倍数（如 9、10、11 等）时 `bps ≥ 1`（无除零），但 `rowsize = TIFFhowmany8(td_bitspersample × tilewidth × samplesperpixel)` 因向上取整而不是 `stride = samplesperpixel` 的整数倍。此时累积循环 `while (count > stride) { REPEAT4(stride, cp[stride] += cp[0]; cp++) ... }` 最后一次 REPEAT4 迭代中 `cp[stride]` 的写入索引超过 `cc-1`，产生堆越界写入。以 `td_bitspersample=9, stride=5, tilewidth=3` 为例：`rowsize=17`，在 count=7 的最后一次 REPEAT4 执行 op2~op4 时写入 `cp0[17]`, `cp0[18]`, `cp0[19]`，超出 17 字节缓冲区 3 字节。当 `stride` 较大（如 65535）时溢出可达数万字节。
- **触发条件**: 攻击者构造一个 TIFF 文件，设置 PREDICTOR 标签值为 3（浮点预测器）、SAMPLEFORMAT 为 SAMPLEFORMAT_IEEEFP（6）、BITSPERSAMPLE 为非 8 的整数倍（如 9、10、17、25 等，须 ≥8 避免除零）、SAMPLESPERPIXEL ≥ 2、PLANARCONFIG = PLANARCONFIG_CONTIG（1），并包含有效的压缩条带/瓦片数据（可为 LZW 或 Deflate 压缩）以触发解码路径。
- **安全影响**: 堆上相邻分配的元数据或对象被写入攻击者影响的值（累积差分计算结果），在可利用的堆布局下可实现远程代码执行（RCE）；至少可导致进程崩溃（DoS）。

## VULN: Heap Buffer OOB Read in fpDiff via Non-Multiple-of-8 BitsPerSample with Floating-Point Predictor
- **漏洞类别**: memory-safety
- **函数**: fpDiff()
- **行号**: 517-548
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen(output) → 编码路径 → PredictorEncodeTile() / PredictorEncodeRow() → fpDiff()
- **描述**: `fpDiff()` 在浮点预测器的编码路径中使用，同样未经 `td_bitspersample` 合法性验证。末尾的差分循环 `cp += cc - stride - 1; for (count = cc; count > stride; count -= stride) REPEAT4(stride, cp[stride] -= cp[0]; cp--)` 以递减方式遍历缓冲区。当 `cc % stride ≠ 0`（由非 8 倍数 bitspersample 触发），最后一次 REPEAT4 迭代中的 `cp[0]` 访问超出缓冲区起始地址之前（负偏移），产生堆越界读取。以 cc=17, stride=5 为例：第 3 次 REPEAT4 中 op2 读取 `cp0[-1]`，op3 读取 `cp0[-2]`，op4 读取 `cp0[-3]`。
- **触发条件**: 与 fpAcc 漏洞触发条件相同（PREDICTOR=3，SAMPLEFORMAT=IEEEFP，BITSPERSAMPLE 非 8 倍数），在 tiffsplit 向输出文件编码写入时触发（输出文件继承输入文件的压缩与预测器设置）。
- **安全影响**: 读取堆分配缓冲区之前的相邻内存内容（可能包含其他分配的数据或指针），导致内存信息泄露；在特定条件下也可能触发访问非法地址导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
