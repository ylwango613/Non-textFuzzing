Now I have all context needed for the complete analysis. Let me consolidate:

**Group 1: EnsureCapacity (line 172)** — `count * sizeof(T)` where `count` is `unsigned int` (32-bit) and `sizeof(T)` is `size_t`. On 32-bit: both 32-bit → multiplication overflows for large `count`. On 64-bit: `unsigned int` is promoted to `size_t` (64-bit) → no overflow in allocation size, but huge allocations throw `std::bad_alloc`.

**Group 2: Callers without bounds checks** — `Ap4CttsAtom.cpp:79`, `Ap4TrunAtom.cpp:127`, `Ap4TfraAtom.cpp:88`, `Ap4Stz2Atom.cpp:89` all call `SetItemCount(file_value)` with no prior validation. Callers WITH bounds checks (stsc, stss, stsz) prevent the overflow.

**Group 3: Secondary integer overflow in Ap4CttsAtom.cpp:80** — `new unsigned char[entry_count*8]` uses 32-bit multiplication (both operands are 32-bit on all platforms); for `entry_count=0x20000001` on 64-bit, this allocates only 8 bytes even if somehow the SetItemCount allocation had succeeded, creating a heap over-read in the loop. But SetItemCount throws before this point on 64-bit.

**Conclusion for 64-bit**: no memory corruption from `EnsureCapacity`. `bad_alloc` → DoS. The secondary buffer overflow (`entry_count*8`) is unreachable after bad_alloc.

**Conclusion for 32-bit**: `count * sizeof(T)` wraps to a tiny value; `operator new` succeeds with a small buffer; `m_AllocatedCount` is set to the huge count; `SetItemCount`'s initialization loop writes massively out-of-bounds → heap overflow. This is a confirmed, externally-triggered memory safety vulnerability.

## VULN: Integer Overflow in EnsureCapacity Leads to Heap Overflow on 32-bit Builds
- **漏洞类别**: memory-safety
- **函数**: AP4_Array<T>::EnsureCapacity()
- **行号**: 166-187 (Ap4Array.h)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory → AP4_CttsAtom::Create() → AP4_CttsAtom::AP4_CttsAtom(size,version,flags,stream) [Ap4CttsAtom.cpp:79] → AP4_Array<AP4_CttsTableEntry>::SetItemCount(entry_count) → AP4_Array<T>::EnsureCapacity(count) [Ap4Array.h:172]
- **描述**: 在 32-bit 构建中，`EnsureCapacity` 第 172 行执行 `::operator new(count * sizeof(T))`，其中 `count` 为 `AP4_Cardinal = unsigned int`（32-bit），`sizeof(T)` 在 32-bit 系统上同样是 32-bit 的 `size_t`，两个 32-bit 无符号整数相乘可发生溢出。当攻击者在 `ctts` box 中指定 `entry_count = 0x20000001`（`AP4_CttsTableEntry` sizeof=8）时，`0x20000001 * 8 = 0x100000008` 在 32-bit 下截断为 `0x8`，`operator new(8)` 仅分配 8 字节，但 `m_AllocatedCount` 被设置为 `0x20000001`。随后 `SetItemCount` 的初始化循环对 `m_Items[0]` 至 `m_Items[0x20000000]`（共 0x20000001 个 8 字节元素）写入大量越界数据，导致堆缓冲区溢出。ctts、trun（`Ap4TrunAtom.cpp:127`）、tfra（`Ap4TfraAtom.cpp:88`）、stz2（`Ap4Stz2Atom.cpp:89`）四个 box 解析器均在调用 `SetItemCount` 前没有对 count 字段进行上界校验，是此漏洞的触发入口。
- **触发条件**: 攻击者构造一个包含 `ctts`（或 `trun`/`tfra`）box 的 MP4 文件，将 `entry_count` 字段设为满足 `entry_count * sizeof(T) mod 2^32` 为极小值的特定值（例如 `0x20000001`），box 的 size 字段可设置为合法的最小值（≥12）。无需实际提供对应数量的条目数据，因为 `stream.Read` 失败时仅 return，不影响已造成的堆损坏。
- **安全影响**: 在 32-bit 构建环境下（含 32-bit Linux 及嵌入式部署），攻击者可通过提供精心构造的 MP4 文件触发堆溢出，可能导致任意代码执行（RCE）。在 64-bit 构建中，`count * sizeof(T)` 作为 64-bit 运算不溢出，但 `entry_count = 0x20000001` 仍会触发对 ~4 GB 内存的分配请求，`operator new` 抛出 `std::bad_alloc` 未被捕获导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
