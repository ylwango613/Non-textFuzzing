Now I have enough context. Let me analyze the findings.

**Key observations in `Ap4UuidAtom.cpp` lines 149-165:**

In both `AP4_UnknownUuidAtom` constructors:
```cpp
m_Data.SetDataSize((AP4_Size)size-GetHeaderSize());
stream.Read(m_Data.UseData(), m_Data.GetDataSize());
```

- `size` is `AP4_UI64` (uint64); `AP4_Size` is `AP4_UI32`
- `GetHeaderSize()` returns 24 (for 32-bit atoms) or 32 (for 64-bit atoms)
- The atom factory check (line 215) only requires `size >= 8`, not `size >= 24`
- If `size = 8..23`: `(AP4_Size)8 - 24 = 0xFFFFFFE8` — unsigned underflow → ~4 GB passed to `SetDataSize`
- The return value of `SetDataSize` is **not checked** in the constructor
- On systems with overcommit (Linux default): allocation of ~4 GB virtual space succeeds, `m_DataSize = 0xFFFFFFE8`, then `stream.Read(ptr, 0xFFFFFFE8)` is called — heap exhaustion / process OOM kill

Additionally, if `size_64 > 0xFFFFFFFF` (large atom), the cast `(AP4_Size)size_64` silently truncates; if the low 32 bits < 32, the same underflow occurs with no 64-bit guard on the subtraction.

## VULN: Integer Underflow in AP4_UnknownUuidAtom Constructor → Uncontrolled Heap Allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_UnknownUuidAtom::AP4_UnknownUuidAtom()
- **行号**: 149-165
- **CWE**: CWE-191 (Integer Underflow / Wrap-or-Wraparound)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File` 解析 → `AP4_AtomFactory::CreateAtomFromStream` (仅检查 `size >= 8`) → 读 16 字节 UUID → `new AP4_UnknownUuidAtom(size_64, uuid, stream)` → 构造函数体 `m_Data.SetDataSize((AP4_Size)size - GetHeaderSize())`
- **描述**: `AP4_UnknownUuidAtom` 两个构造函数（`Ap4UuidAtom.cpp:153` 和 `:164`）在计算 payload 大小时，将 `AP4_UI64` 的 `size` 强制转换为 `AP4_Size`（即 `AP4_UI32`）后再减去 `GetHeaderSize()`（24 或 32）。atom factory 仅检查 `size >= 8`，未对 UUID atom 做最小 24 字节的特定检查。当攻击者将 UUID atom 的 size 字段设置为 8–23 时，`(AP4_Size)size - 24` 发生无符号整数下溢，结果约为 `0xFFFFFFE8`（~4 GB），该值被直接传入 `SetDataSize()`；`SetDataSize` 的返回值在构造函数中未被检查，若系统启用了内存过提交（Linux 默认），分配成功后 `m_DataSize` 被设为 ~4 GB，随即调用 `stream.Read(ptr, ~4 GB)`，导致进程消耗大量内存。此外，当 `size_64 > 0xFFFFFFFF` 且低 32 位小于 `GetHeaderSize()` 时，截断后同样触发相同路径。
- **触发条件**: 构造包含一个 type=`uuid`、size 字段值在 8–23 范围内（如 `\x00\x00\x00\x08uuid`）的 MP4 atom；atom factory 的通用检查（`size >= 8`）会放行此输入，随后进入 UUID 分支时不再做针对 UUID header 最小尺寸的保护。
- **安全影响**: 攻击者可利用单个格式错误的 MP4 文件中的一个微小 UUID atom，使目标进程分配约 4 GB 的堆内存，导致进程 OOM 终止（DoS）；在内存过提交场景下，`stream.Read` 将以 ~4 GB 为读取目标写入分配的 heap 区域，亦可能引发 heap 区域的越界访问。

<!-- AUDIT_PROMPT_VERSION: 1 -->
