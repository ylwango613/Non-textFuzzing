I have all the information needed. Let me now analyze the complete picture:

**Key findings from the code analysis:**

`AP4_Cardinal` = `unsigned int` (32-bit), `AP4_UI08` = `unsigned char`.

In `Ap4Stz2Atom.cpp` line 90:
```cpp
unsigned int table_size = (sample_count*m_FieldSize+7)/8;
```
- `sample_count` (32-bit `unsigned int`) × `m_FieldSize` (8-bit, promoted to `unsigned int`) is a **32-bit multiplication with no overflow guard**.
- With `sample_count = 0x20000000` and `m_FieldSize = 16`: product = `0x200000000` → wraps to `0`, so `table_size = 0`.
- Line 91 check `(0 + 8) > size` passes for any attacker-supplied `size ≥ 9`.
- `buffer = new unsigned char[0]` — **zero-byte allocation**.
- `stream.Read(buffer, 0)` reads nothing.
- The loop at lines 116–118 (`for (i=0; i<sample_count; i++) { m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2]); }`) reads `buffer[0]`, `buffer[2]`, …, `buffer[2*(sample_count-1)]` → **massive OOB heap read** past the zero-byte buffer.
- `m_Entries.SetItemCount(sample_count)` return value at line 89 is **not checked**; if allocation fails, indexed access `m_Entries[i]` follows a null or stale pointer → crash/OOB write.

## VULN: Integer Overflow in stz2 table_size Leading to Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 88-120
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::Parse() → AP4_AtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create() → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: 在解析 stz2 box 的私有构造函数中，`m_SampleCount` 直接从文件读入（`stream.ReadUI32(m_SampleCount)`，无边界校验），随后赋给 `AP4_Cardinal sample_count`（32 位无符号整数）。第 90 行 `unsigned int table_size = (sample_count * m_FieldSize + 7) / 8` 中，两个操作数均为 32 位，乘法可发生无符号 32 位整数溢出：当 `sample_count = 0x20000000`、`m_FieldSize = 16` 时，`0x20000000 * 16 = 0x200000000` 截断为 `0`，致使 `table_size = 0`。第 91 行边界检查 `(0 + 8) > size` 对攻击者指定的任意 `size ≥ 9` 均不成立，程序继续以 `new unsigned char[0]` 分配零字节缓冲区 `buffer`，然后在 `case 16` 分支中执行 `for (i = 0; i < 0x20000000; i++) { m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2]); }`，访问 `buffer[0]`、`buffer[2]`、……、`buffer[0x3FFFFFFE]`，大幅越界读取堆内存（逾 536 MB 范围），将堆元数据及相邻对象内容写入 `m_Entries` 数组，造成堆信息泄露及潜在的二次内存破坏。此外，第 89 行 `m_Entries.SetItemCount(sample_count)` 的返回值未被检查；若内部 2 GB 内存分配失败，`m_Entries.m_Items` 保持空指针，后续 `m_Entries[i]` 即为空指针解引用，引发崩溃。
- **触发条件**: 构造一个 stz2 box，其中 `field_size = 16`、`sample_count = 0x20000000`（或满足 `sample_count * 16 mod 2^32 < small_value` 的任意值）、box `size` 字段设为任意大于 8 的值（如 0x20）；实际 box payload 中仅提供极少字节。将该 box 嵌入 moov/trak/mdia/minf/stbl 层级后喂给 mp42aac。
- **安全影响**: 在 64 位 Linux（启用 overcommit）上，`m_Entries` 的 2 GB 虚拟内存分配可成功，程序随后大量越界读取堆内存并将其内容（含 glibc 堆元数据、指针残留、相邻对象数据）存入 `m_Entries`；这些被污染的 sample size 值随后被用于进一步分配和文件偏移计算，可能转化为 RCE；在 32 位或低内存环境下，分配失败导致空指针解引用，进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
