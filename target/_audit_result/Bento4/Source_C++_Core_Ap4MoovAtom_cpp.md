Now I have a complete picture. Let me consolidate findings from the full parsing chain accessible through Ap4MoovAtom.cpp.

**Summary of analysis:**

- `Ap4MoovAtom.cpp` (137 lines) itself is thin—collects trak atoms, delegates parsing to `AP4_ContainerAtom::ReadChildren` → `atom_factory.CreateAtomFromStream`.
- The attack surface is in the child atoms parsed transitively: stco, co64, ctts, stsz, stts, stsc.

**Finding 1 — ctts (Ap4CttsAtom.cpp:77-97):** `entry_count` read from file with zero bounds check. Then `new unsigned char[entry_count*8]` — the multiplication is AP4_UI32 × int → unsigned 32-bit arithmetic, overflowing to 0 or a tiny value when `entry_count ≥ 0x20000000`. The subsequent loop iterates `entry_count` times reading `&buffer[i*8]`, producing a heap OOB read from a tiny buffer against the large backing `m_Entries` array.

**Finding 2 — stco (Ap4StcoAtom.cpp:78-90):** Bounds check `m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4)/4` performs unsigned 32-bit subtraction. When `size < 16` (valid, since `Create()` only requires `size ≥ 12 = AP4_FULL_ATOM_HEADER_SIZE`), the subtraction underflows to a huge value, effectively disabling the clamp and allowing arbitrary `m_EntryCount` → uncontrolled allocation → OOM crash.

## VULN: AP4_CttsAtom Integer Overflow in Buffer Allocation → Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-97 (Ap4CttsAtom.cpp)
- **CWE**: CWE-122 (Heap-based Buffer Overflow) / CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac::main → new AP4_File(*input) → AP4_File parses moov → AP4_MoovAtom::AP4_MoovAtom → AP4_ContainerAtom::ReadChildren → atom_factory.CreateAtomFromStream → AP4_CttsAtom::Create → new AP4_CttsAtom(size, version, flags, stream)
- **描述**: `AP4_CttsAtom` 构造函数在读取 `entry_count`（来自文件）后，没有任何边界校验，直接执行 `m_Entries.SetItemCount(entry_count)` 和 `new unsigned char[entry_count*8]`。后者的乘法在 AP4_UI32（32位无符号整数）精度下计算：当 `entry_count ≥ 0x20000000`（536870912）时，`entry_count * 8` 的 32位结果溢出归零（或变为极小值），传递给 `new` 后仅分配几字节的缓冲区。随后 `for (unsigned i=0; i<entry_count; i++)` 循环从这个几字节的缓冲区中读取 `&buffer[i*8]`，当 `i≥1` 时即产生堆越界读取。当 `entry_count` 足够大导致 `m_Entries.SetItemCount` 先行 OOM 时，则触发进程崩溃（DoS）；在内存充足（≥4 GB 可用堆）的系统上，两次分配均可成功，而 `buffer` 仅有数字节，循环中读取 `buffer[i*8]` 越界访问堆上任意区域，造成堆越界读。
- **触发条件**: 构造一个 MP4 文件，令 `moov/trak/mdia/minf/stbl/ctts` box 中 `entry_count` 字段为 `0x20000001`（或任何 `≥ 0x20000000` 的值）。ctts box 的 `size` 字段可设置为最小合法值（≥ 12）。无需其他特殊条件。
- **安全影响**: 最轻后果为进程崩溃（DoS），由 OOM 或 SIGSEGV 触发；在高内存服务器（≥4 GB 可用）上，循环读取的 `buffer[i*8]`（`i` 最大为 0x1FFFFFFF，对应偏移 0xFFFFFFF8 ≈ 4GB）可越界读取堆上任意内存，导致潜在的进程内信息泄露（堆内容泄漏）；若与堆布局控制结合，理论上可用于 RCE。

## VULN: AP4_StcoAtom Unsigned Integer Underflow in Bounds Check → Uncontrolled OOM
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom()
- **行号**: 78-81 (Ap4StcoAtom.cpp)
- **CWE**: CWE-191 (Integer Underflow) / CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 6.2 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac::main → new AP4_File(*input) → AP4_File parses moov → AP4_MoovAtom::AP4_MoovAtom → AP4_ContainerAtom::ReadChildren → atom_factory.CreateAtomFromStream → AP4_StcoAtom::Create → new AP4_StcoAtom(size, version, flags, stream)
- **描述**: `AP4_StcoAtom` 构造函数中的越界校验为 `m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4`，三个操作数均为 AP4_UI32 类型（无符号 32 位整数）。`AP4_StcoAtom::Create()` 仅校验 `size >= AP4_FULL_ATOM_HEADER_SIZE`（即 ≥ 12），因此 size 可取 12、13、14、15 等值。当 `size < 16` 时，`size - 12 - 4` 在无符号 32 位下发生下溢（如 size=12 时结果为 0xFFFFFFFC），除以 4 得到约 10 亿（0x3FFFFFFF）的巨大阈值，使 clamp 形同虚设。攻击者可令 `m_EntryCount`（来自文件）为任意值通过检查，后续 `new AP4_UI32[m_EntryCount]` 和 `new unsigned char[m_EntryCount*4]` 将尝试分配数 GB 内存，导致不受控的内存分配并进程崩溃。
- **触发条件**: 构造 MP4 文件中 `moov/trak/mdia/minf/stbl/stco` box 的 `size` 字段设为 12（或 13–15），并将 `entry_count` 字段设为大值（如 0x3FFFFFFF），使得 `new AP4_UI32[0x3FFFFFFF]` 请求约 4 GB 内存。
- **安全影响**: 必然导致进程因未捕获的 `std::bad_alloc` 异常而终止（DoS）；由于程序没有全局 `try/catch`，每次处理此类构造的 MP4 文件均可可靠地使进程崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
