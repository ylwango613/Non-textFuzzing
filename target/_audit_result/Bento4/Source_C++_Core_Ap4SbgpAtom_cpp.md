Now I have all the context needed. Let me analyze the key vulnerability in detail:

**Analysis of `Ap4SbgpAtom.cpp`:**

**Line 87:** `if (remains < entry_count*8)`
- `entry_count` is `AP4_UI32` = `unsigned int` (32-bit per Ap4Types.h line 45)
- `8` is `int` (32-bit)
- C++ converts `int` to `unsigned int` → multiplication is 32-bit unsigned → wraps mod 2^32
- With `entry_count = 0x20000000`: `0x20000000 * 8 = 0x100000000 mod 2^32 = 0`
- Check becomes: `remains < 0` → always false → **bounds check completely bypassed**

**Line 90:** `m_Entries.SetItemCount(entry_count)` — return value **not checked**

**In `EnsureCapacity` (Ap4Array.h line 172):** `::operator new(count * sizeof(T))`
- `count` = `AP4_Cardinal` = `unsigned int` (32-bit), `sizeof(Entry)` = 8
- **64-bit system:** `count` promoted to 64-bit → `0x20000000ULL * 8 = 0x100000000` (4GB) → `std::bad_alloc` → unhandled exception → DoS
- **32-bit system:** `count * sizeof(T)` = `0x20000000 * 8 = 0` (overflow) → `::operator new(0)` returns a tiny valid pointer, but `m_AllocatedCount` is set to `0x20000000`

**Lines 91-96 loop:** `m_Entries[i] = entry` for i from 0 to `entry_count-1` — on 32-bit, writes 0x20000000 × 8 bytes past a 0-byte heap allocation → **massive heap buffer overflow**.

## VULN: Integer overflow in entry_count*8 bounds check bypasses guard, enabling heap buffer overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_SbgpAtom::AP4_SbgpAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 87-96
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac(main) → AP4_File::AP4_File(stream) → atom parsing → AP4_SbgpAtom::Create(size, stream) → AP4_SbgpAtom::AP4_SbgpAtom(size, version, flags, stream) → line 87 bounds check bypass → line 90 SetItemCount(huge) → AP4_Array::EnsureCapacity → ::operator new(overflow=0) → lines 91-96 heap write loop
- **描述**: 在 sbgp atom 构造函数第 87 行，`entry_count`（`AP4_UI32`，32位无符号）乘以字面量 `8`（`int`），C++ 将 `int` 提升为 `unsigned int` 后执行 32 位无符号乘法。当攻击者将 `entry_count` 设为 `0x20000000` 时，`entry_count * 8 = 0x100000000 mod 2^32 = 0`，使得 `remains < 0` 恒为 false，完全绕过边界校验。随后第 90 行 `m_Entries.SetItemCount(0x20000000)` 的返回值未被检查；在 `EnsureCapacity` 中，32位系统上 `count * sizeof(T) = 0x20000000 * 8 = 0`（也溢出），`::operator new(0)` 返回一个仅含 0 字节的合法指针，但 `m_AllocatedCount` 被设为 `0x20000000`；第 91–96 行的循环随后以 `0x20000000` 次迭代向该指针后写入 8 字节，造成巨型堆缓冲区溢出。在 64 位系统上，`EnsureCapacity` 中 `count * sizeof(T)` 提升为 64 位后得到 4GB，`::operator new(4GB)` 抛出未被捕获的 `std::bad_alloc` 导致进程崩溃（DoS）。
- **触发条件**: 构造一个包含 `sbgp` box 的 MP4 文件，其中 `sbgp` box 的 `entry_count` 字段设置为 `0x20000000`（或任意使 `entry_count * 8` 在 32 位算术下溢出的值，如 `0x40000000`、`0x60000000` 等），`size` 字段设为合法的大于等于 `AP4_FULL_ATOM_HEADER_SIZE`（12）的值，atom body 包含该 entry_count 值但实际 entry 数据可任意。
- **安全影响**: 在 32 位目标上：堆缓冲区溢出覆盖任意堆内存，可被利用实现远程代码执行（RCE）；在 64 位目标上：未处理的 `std::bad_alloc` 异常导致进程立即崩溃（DoS）。最坏情况为攻击者完全控制进程执行流。

<!-- AUDIT_PROMPT_VERSION: 1 -->
