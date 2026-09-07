I have now completed reading all relevant files. Let me compile my analysis findings into the required report format.

**Batch 1 analysis (Ap4AtomSampleTable.cpp lines 1-367):** The file itself (GetSample, GetSampleCount, GetChunkForSample, etc.) uses defensive patterns — result checking, `skip > index` guard against underflow. No direct memory corruption in the table file itself.

**Batch 2 analysis (child atom constructors):**

- **Ap4StszAtom.cpp line 78**: bounds check `m_SampleCount > (size-8)/4` is off by 3 entries vs correct formula `(size-20)/4`, but only causes 12-byte stream over-read into correctly-sized buffer — not a memory safety bug.
- **Ap4StcoAtom.cpp line 78**: bounds check present, correctly caps m_EntryCount. Max allowed m_EntryCount × 4 < 2^32 — no overflow. Safe.
- **Ap4StscAtom.cpp line 78**: bounds check `(size-12)/12 < entry_count` — max allowed entry_count is 357913940 < 357913942 (the overflow threshold for ×12) — overflow prevented. Safe.
- **Ap4SttsAtom.cpp**: uses `Append` in a while-loop bounded by stream availability, no direct `new[count]` with file-controlled count. Safe.
- **Ap4StssAtom.cpp line 78**: check present, uses `AP4_ATOM_HEADER_SIZE` (8) instead of `AP4_FULL_ATOM_HEADER_SIZE` (12) allowing 1 extra entry — trivial stream over-read only.
- **Ap4CttsAtom.cpp lines 78-96**: **NO bounds check at all**, AND `entry_count * 8` uses 32-bit unsigned arithmetic that overflows when `entry_count >= 0x20000000`. `m_Entries.SetItemCount(entry_count)` uses 64-bit arithmetic (EnsureCapacity promotes to `size_t`), while `new unsigned char[entry_count*8]` stays 32-bit → buffer is zero-sized; loop then reads `buffer[i*8]` for 536M iterations = massive heap OOB read.
- **Ap4Stz2Atom.cpp line 90**: `table_size = (sample_count*m_FieldSize+7)/8` — both operands are 32-bit, can overflow for large sample_count. But stsz-style access bounds through SetItemCount (which uses 64-bit internally) diverges from the allocated buffer. Similar pattern to ctts but less severe due to SetItemCount potentially failing first.

---

## VULN: AP4_CttsAtom Integer Overflow → Heap Out-of-Bounds Read
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-97
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_AtomFactory::CreateAtomFromStream → AP4_CttsAtom::Create → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream) [Ap4CttsAtom.cpp:68] → line 79: stream.ReadUI32(entry_count) → line 80: m_Entries.SetItemCount(entry_count) → line 81: new unsigned char[entry_count*8] (overflow) → line 82: stream.Read(buffer, entry_count*8) → line 88-96: loop reads buffer[i*8] OOB
- **描述**: `Ap4CttsAtom.cpp` 的解析构造函数中，`entry_count` 直接从 MP4 文件字节流读入，且没有任何与 atom 大小的边界校验（其他 atom 如 stco/stsz/stsc 均有此检验）。`m_Entries.SetItemCount(entry_count)` 通过 `EnsureCapacity` 内部使用 `size_t`（64 位）算术，可正常为 entry_count 个条目分配内存；但紧随其后的 `new unsigned char[entry_count*8]`（第 81 行）使用 `AP4_UI32 * int` 的 32 位无符号乘法，当 `entry_count >= 0x20000000`（536,870,912）时，`entry_count*8` 溢出为 0 或极小值，导致 `buffer` 被分配为 0 字节（`new unsigned char[0]`）。随后 `stream.Read(buffer, 0)` 实际上不读任何数据。循环 `for (unsigned i=0; i<entry_count; i++) { ... AP4_BytesToUInt32BE(&buffer[i*8]) ... }` 对 `buffer[8], buffer[16], ...` 等越界偏移做堆读取，越界范围从 8 字节到 `0x1FFFFFFF*8 ≈ 4GB`，遍历整个进程堆空间。
- **触发条件**: 构造一个 MP4 文件，在 moov/trak/mdia/minf/stbl 中嵌入 ctts box，将其 `entry_count` 字段设置为 `0x20000000`（或 `0x20000001` 等使 entry_count*8 溢出为小值的任意数）。文件中 ctts box 的声明大小（size 字段）不需要与 entry_count 匹配（缺少边界检验）。在 Linux 64 位系统（默认内存过量提交 `vm.overcommit_memory=0` 或 =1）运行 `mp42aac crafted.mp4 out.aac`，文件解析阶段即触发漏洞。
- **安全影响**: 堆越界读取可造成（1）进程崩溃（DoS）——循环迭代 5 亿次访问超量虚拟内存，触发 OOM killer；（2）堆信息泄露——从 `buffer` 相邻堆块读取的任意数据（堆指针、栈地址、密钥材料等）写入 `m_Entries` 数组中，若后续被转储或用于解密则可能导致信息泄露；（3）若配合其他漏洞，可能辅助绕过 ASLR。

## VULN: AP4_CttsAtom Missing entry_count Bounds Check → Uncontrolled Memory Allocation (DoS)
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 78-82
- **CWE**: CWE-789 (Uncontrolled Memory Allocation) / CWE-400 (Uncontrolled Resource Consumption)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_AtomFactory::CreateAtomFromStream → AP4_CttsAtom::Create → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream) → line 79: stream.ReadUI32(entry_count) [无任何 size 边界检验] → line 80: m_Entries.SetItemCount(entry_count) 分配巨量内存 → OOM crash
- **描述**: ctts atom 构造函数在读取 `entry_count` 后（第 79 行），直接调用 `m_Entries.SetItemCount(entry_count)`（第 80 行）和 `new unsigned char[entry_count*8]`（第 81 行），没有任何校验 `entry_count` 是否在 atom 大小所允许的范围之内。对比同文件夹内的 stco（`if (m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4)`）、stsz（`if (m_SampleCount > (size-8)/4)`）、stsc（`if ((size-AP4_ATOM_HEADER_SIZE-4)/12 < entry_count)`），ctts 完全缺失此类防御。攻击者可将一个 atom size 仅为 16 字节的 ctts box 中的 `entry_count` 设置为 50,000,000，迫使解析器试图分配 400MB（m_Entries）+ 400MB（buffer）= 共 800MB 内存，并随后调用 `stream.Read(buffer, 400MB)` 从文件流读取远超 atom 边界的数据。
- **触发条件**: 构造 ctts box：size 字段设置为 16（只含头部和 entry_count，不含任何条目数据），`entry_count` 字段设置为 50,000,000 或更大（但需 <0x20000000 以避免整数溢出触发另一漏洞路径）。运行 `mp42aac crafted.mp4 out.aac`，文件解析即触发。
- **安全影响**: 进程尝试分配远超 atom 实际内容的内存和读取超量流数据，导致（1）OOM 崩溃（DoS）——系统可用内存耗尽；（2）信息泄露——从超出 atom 边界的文件区域读取数据（来自其他 box 的内容）写入堆中。在批量解析场景下（如媒体服务器）可造成持续性拒绝服务。

<!-- AUDIT_PROMPT_VERSION: 1 -->
