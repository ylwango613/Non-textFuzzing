I have now fully analyzed all relevant code. Here is my complete finding.

**Analysis summary before writing the final report:**

- `DiracParseUnit.next_pu_offset` / `prev_pu_offset` are `int` (line 97-98) but populated from `AV_RB32()` (returns `uint32_t`) at lines 118-119.
- Values ≥ 0x80000000 become negative ints and are correctly rejected by the `< 13` check on lines 132-134.
- Values in `[13, 0x7FFFFFFF]` pass all validation and are legitimately large.
- `pc->dirac_unit_size` (an `int`) accumulates `pu.next_pu_offset` at line 205 on every valid parse unit found. For **non-picture** parse units the function returns -1 without resetting `pc->dirac_unit_size` (reset only at line 233 after a complete picture unit).
- Two consecutive non-picture parse units each with `next_pu_offset = 0x40000001` (≈1 GB, perfectly legal per the checks) yield: `0x40000001 + 0x40000001 = 0x80000002` → signed overflow → `pc->dirac_unit_size = -2147483646`.
- The safety guard on line 190 (`pc->index < pc->dirac_unit_size + 13LL + pu1.prev_pu_offset`) then computes a **negative** 64-bit value on the RHS (≈ -1,073,741,808) and is **always false** for non-negative `pc->index`, so it is completely bypassed.
- The pointer on lines 202-203 then evaluates to `pc->buffer + pc->index − 13 − N + 2147483646`, which is roughly **+1 GB past the end of the allocated heap buffer**.
- This out-of-bounds pointer is handed to the Dirac decoder at lines 230-231 (`*buf = pc->dirac_unit`), causing a heap out-of-bounds read.

---

## VULN: Integer Overflow in dirac_unit_size Causes Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: dirac_combine_frame()
- **行号**: 190-231
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted Dirac media file / stream
- **外部触发路径**: `ffmpeg -i <crafted.drc> -f null -` → `avformat_open_input()` → codec parser framework → `dirac_parse()` (line 240) → `dirac_combine_frame()` (line 261) → heap OOB read at line 230 when overflowed `pc->dirac_unit` is returned
- **描述**: `pc->dirac_unit_size`（`int` 型，DiracParseContext 成员）在 `dirac_combine_frame()` 的第 205 行通过 `pc->dirac_unit_size += pu.next_pu_offset` 对每个合法解析单元累积偏移量。对于非图像型解析单元（`(pu.pu_type & 0x08) != 0x08`），函数提前在第 207-211 行 return -1 而**不重置** `pc->dirac_unit_size`（仅在第 233 行完整图像帧完成后重置）。`pu.next_pu_offset` 由 `AV_RB32()`（返回 `uint32_t`）赋值给 `int` 字段（第 118 行），合法范围为 [13, 0x7FFFFFFF]。两个连续非图像单元各携带 `next_pu_offset = 0x40000001`（≈1 GB），累加后 `0x40000001 × 2 = 0x80000002` 超过 `INT_MAX`，发生有符号整数溢出，`pc->dirac_unit_size` 变为 `-2147483646`。此时第 190 行安全检查 `pc->index < pc->dirac_unit_size + 13LL + pu1.prev_pu_offset` 的右侧计算为约 `-1,073,741,808`，对任何非负 `pc->index` 永远为 false，检查完全失效。第 202-203 行计算 `pc->dirac_unit = pc->buffer + pc->index - 13 - pu1.prev_pu_offset - pc->dirac_unit_size`；由于 `pc->dirac_unit_size` 为大负值，减去它等于加上约 +2GB，导致指针超出分配堆缓冲区约 1 GB。该越界指针在第 230-231 行作为输出缓冲区 `*buf` 返回给 Dirac 解码器，解码器从越界地址读取数据，触发堆越界读。
- **触发条件**: 攻击者构造一个 Dirac 码流，其中包含至少两个连续的**非图像**类型解析单元（如 pu_type=0x00 Sequence Header），每个单元的 `next_pu_offset` 字段（码流字节偏移 5-8）设置为 `0x40000001`（约 1 GB），且 `prev_pu_offset` 字段与前一单元 `next_pu_offset` 一致（满足 `pu.next_pu_offset == pu1.prev_pu_offset` 验证）。每个解析单元仅需 13 字节合法头，单元间数据为任意内容，总文件大小约 2 GB。之后紧跟一个图像型解析单元（pu_type bit 0x08 置位），触发第 230 行越界指针的实际读取。
- **安全影响**: 最坏情况下，Dirac 解码器从越界堆地址读取数据，可导致：(1) 崩溃/DoS（SIGSEGV，最可能发生）；(2) 在内存布局可预测的环境（如媒体转码服务器、容器内的 FFmpeg）中，泄露相邻堆内存内容（信息泄露），可能包含密钥、帧缓冲区数据等敏感信息；(3) 若与其他内存原语链式利用，理论上可升级为远程代码执行。

<!-- AUDIT_PROMPT_VERSION: 1 -->
