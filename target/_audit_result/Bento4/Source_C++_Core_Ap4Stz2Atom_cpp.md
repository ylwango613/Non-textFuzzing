Now I have all the context needed. Let me analyze the code carefully.

**Group 1 analysis — constructor (lines 71–122):**

Key sequence:
- Line 82: `stream.ReadUI32(m_SampleCount)` — `m_SampleCount` is `AP4_UI32`, fully attacker-controlled
- Line 88: `AP4_Cardinal sample_count = m_SampleCount;` — still `AP4_UI32`
- Line 89: `m_Entries.SetItemCount(sample_count);` — return value **unchecked**
- Line 90: `unsigned int table_size = (sample_count*m_FieldSize+7)/8;`
  - `sample_count` is `uint32_t`, `m_FieldSize` is `uint8_t` (valid values: 4, 8, 16)
  - Multiplication is in 32-bit unsigned arithmetic → **integer overflow possible**
  - With `m_FieldSize=16`, `sample_count=0x10000000`: `0x10000000*16 = 0x100000000` wraps to **0** → `table_size = 0`
- Line 91: `if ((table_size+8) > size) return;` — with `table_size=0` this checks `8 > size`; attacker sets box `size` >> 8, check **passes**
- Line 92: `buffer = new unsigned char[0]` — zero-byte allocation
- Line 93: `stream.Read(buffer, 0)` — reads 0 bytes, succeeds
- Lines 116–119, case 16: `for (i=0; i<sample_count; i++) { m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2]); }` — reads from 0-byte `buffer` for `0x10000000` iterations → **massive heap OOB read**

The `m_Entries.SetItemCount(0x10000000)` path in `EnsureCapacity` calls `::operator new(0x10000000 * 4 = 1 GB)`. If that succeeds, `m_Items` is valid but `buffer` is zero-byte; the loop then reads beyond it. If it throws OOM and m_Items remains NULL, then `m_Entries[i]` in the loop is a null-pointer dereference. Either way, the invariant breaks because `table_size` underflows and the protective check at line 91 fails to catch it.

---

## VULN: Integer overflow in stz2 table_size leads to heap OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 90-120
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create() → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: 在解析 stz2 box 时，第 90 行用无符号 32 位整数计算 `table_size = (sample_count * m_FieldSize + 7) / 8`。`sample_count`（AP4_UI32）和 `m_FieldSize`（AP4_UI08，合法值 4/8/16）的乘积在 32 位无符号算术中会溢出：当 `m_FieldSize=16`、`sample_count=0x10000000` 时，乘积 `0x100000000` 截断为 0，`table_size` 变为 0。随后第 91 行的保护性检查 `(table_size+8) > size` 变为 `8 > size`，攻击者将 box size 设为任意大值即可绕过此检查。接着第 92 行分配 0 字节的 `buffer`，第 93 行 `stream.Read(buffer, 0)` 成功读取 0 字节，然后第 116–119 行的循环以 `i` 从 0 到 `sample_count-1`（共 2.68 亿次）迭代，每次访问 `buffer[i*2]`——这远超 0 字节缓冲区边界，造成大规模堆越界读取。
- **触发条件**: 构造一个包含 `stz2` box 的 MP4 文件，设置 `field_size=16`、`sample_count=0x10000000`（或其他使 `sample_count * field_size` mod 2^32 得到极小值的组合），并将 box `size` 字段设为大于 8 的任意值（如 0xFFFFFFFF）。
- **安全影响**: 堆越界读取可泄露同一进程中其他堆分配对象的内存内容（信息泄露），或在访问未映射页时触发段错误导致进程崩溃（DoS）。在将 Bento4 用作服务端媒体处理库的场景下，可利用泄露的堆数据绕过 ASLR，进而辅助 RCE 利用链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
