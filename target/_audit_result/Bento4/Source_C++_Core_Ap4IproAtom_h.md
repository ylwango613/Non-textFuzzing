I have all the information needed. Let me analyze the vulnerability:

**Key facts:**
- `AP4_FULL_ATOM_HEADER_SIZE` = 12 (line 61 of Ap4Atom.h)
- `AP4_LargeSize` = 64-bit unsigned integer
- Guard in `Create()`: `if (size < AP4_FULL_ATOM_HEADER_SIZE) return NULL` — only checks `size >= 12`
- Line 70 in constructor: `AP4_LargeSize bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 2`

**Integer underflow analysis:** When `size == 12` (passes guard: `12 >= 12`), the arithmetic is:
`12 - 12 - 2 = -2` as `AP4_UI32` (unsigned 32-bit) → wraps to `0xFFFFFFFE`, zero-extended to `AP4_LargeSize` = `0x00000000FFFFFFFE` (~4 GB).

In `CreateAtomFromStream` line 215: `if (size > bytes_available)` — with `bytes_available = 0xFFFFFFFE`, any atom size passes this check, allowing atom parsing far beyond the `ipro` box's declared boundary. The attacker controls what data follows the `ipro` atom in the file, and those bytes get parsed as `ipro` children, triggering cascading heap allocations from attacker-controlled sizes.

## VULN: Integer Underflow in AP4_IproAtom Constructor Causes OOB Read and Unbounded Atom Parsing
- **漏洞类别**: memory-safety
- **函数**: AP4_IproAtom::AP4_IproAtom()
- **行号**: 70-79
- **CWE**: CWE-191 (Integer Underflow leading to CWE-125 Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::ParseStream() → AP4_AtomFactory::CreateAtomFromStream() → AP4_IproAtom::Create() → new AP4_IproAtom(size=12, ...) → constructor line 70: `bytes_available = 12 - 12 - 2 = 0xFFFFFFFE (32-bit wrap) → 0x00000000FFFFFFFE (64-bit)` → loop calls CreateAtomFromStream with huge bytes_available
- **描述**: 构造函数第 70 行计算 `AP4_LargeSize bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 2`，其中 `size` 为 `AP4_UI32`（来自文件字段），`AP4_FULL_ATOM_HEADER_SIZE = 12`。`Create()` 的守卫只检查 `size < 12`（返回 NULL），但未检查 `size < 14`（12+2）。当攻击者设置 `size = 12` 或 `size = 13` 时，32 位无符号减法下溢：`12 - 12 - 2 = 0xFFFFFFFE`，零扩展为 64 位后赋给 `bytes_available`，得到约 4 GB 的值。随后循环以此巨大的 `bytes_available` 调用 `CreateAtomFromStream`（`Ap4AtomFactory.cpp:215` 的边界检查 `size > bytes_available` 因此对几乎任何 atom 大小都通过），导致解析器越过 `ipro` 声明边界，将后续文件字节（攻击者完全控制）作为 `ipro` 子 atom 解析，触发基于攻击者控制尺寸的堆分配。
- **触发条件**: 构造一个 MP4 文件，包含 `ipro` atom，其 size 字段设置为 12（最小合法值，仅包含 full atom header），之后紧接攻击者控制的 atom 数据；同时将 `entry_count`（UI16，从 atom 边界外读取）设置为非零值以驱动循环迭代。
- **安全影响**: 1) 越界读——解析器读取 `ipro` 声明范围外的文件字节并将其解释为子 atom，导致信息泄露；2) 堆内存破坏——被错误解析的 atom 若包含大 count/size 字段，将触发基于攻击者控制值的堆分配，在最坏情况下可达到任意堆写入（RCE）；3) 拒绝服务——无效内存访问导致崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
