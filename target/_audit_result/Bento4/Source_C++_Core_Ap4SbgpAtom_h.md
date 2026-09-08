Now I have all context needed. Let me analyze the vulnerabilities:

**Analysis of `Ap4SbgpAtom.cpp` constructor (lines 68–97):**

1. `AP4_UI32 remains = size - GetHeaderSize()` — `GetHeaderSize()` returns 12 for a full atom. `Create()` only guards `size >= 12`, so `remains` starts at 0 when `size == 12`.
2. `remains -= 4` (line 78) — no prior check that `remains >= 4`. Wraps to `0xFFFFFFFC` when `remains == 0`.
3. `remains -= 4` again (lines 81, 86) — further underflows.
4. Line 87: `if (remains < entry_count*8)` — both `remains` and `entry_count` are `AP4_UI32`; the multiplication `entry_count * 8` is computed in 32-bit unsigned arithmetic. With `entry_count = 0x20000000`, result is `0` (wraps), making `remains < 0` always false → bounds check bypassed.
5. Line 90: `m_Entries.SetItemCount(entry_count)` — **return value is ignored**.
6. `EnsureCapacity` calls `::operator new(count * sizeof(T))`: on 32-bit, `0x20000000 * 8` wraps to `0` → allocates nearly nothing, but `m_AllocatedCount` / `m_ItemCount` are set to `0x20000000` → subsequent loop at line 91–96 writes 536M entries far beyond the tiny buffer → **heap buffer overflow**.

---

## VULN: Integer overflow in entry_count*8 bypasses sbgp bounds check → heap buffer overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_SbgpAtom::AP4_SbgpAtom()
- **行号**: 87-96
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_SbgpAtom::Create() → new AP4_SbgpAtom(size, version, flags, stream) → constructor line 87-96
- **描述**: 在 `AP4_SbgpAtom` 构造函数（Ap4SbgpAtom.cpp:87）中，边界检查 `if (remains < entry_count*8)` 使用 32 位无符号乘法（`entry_count` 为 `AP4_UI32`）。当 `entry_count = 0x20000000`（536870912）时，`entry_count * 8 = 0x100000000`，截断为 `AP4_UI32` 后得到 `0`，导致 `remains < 0` 恒假，检查被完全绕过。随后 `m_Entries.SetItemCount(entry_count)` 的返回值被忽略（line 90）；在 32 位构建中，`EnsureCapacity` 内部 `count * sizeof(T)` 同样溢出为 `0`，`operator new(0)` 仅分配极小缓冲区，但 `m_ItemCount` 被设置为 `0x20000000`，导致 lines 91-96 的循环向越界内存连续写入 536M 个 Entry（每个 8 字节），造成堆缓冲区溢出。在 64 位构建中，`operator new` 以 4GB 参数调用并抛出 `std::bad_alloc`，造成进程崩溃（DoS）。
- **触发条件**: 构造一个包含 `sbgp` box 的 MP4 文件，其中 `entry_count` 字段设为 `0x20000000`（或任意满足 `entry_count * 8 ≡ 0 (mod 2^32)` 的值，如 `0x40000000`），`size` 字段设为任意合法值（≥ 12）。
- **安全影响**: 32 位构建：堆缓冲区溢出，可覆盖任意堆内存，具备代码执行（RCE）潜力；64 位构建：进程因 `std::bad_alloc` 终止（DoS）。攻击者仅需提供一个精心构造的 MP4 文件，无需任何权限。

## VULN: Integer underflow in remains makes bounds check bypass trivial for any entry_count
- **漏洞类别**: memory-safety
- **函数**: AP4_SbgpAtom::AP4_SbgpAtom()
- **行号**: 76-88
- **CWE**: CWE-191 (Integer Underflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_SbgpAtom::Create()（仅检查 `size >= AP4_FULL_ATOM_HEADER_SIZE=12` 即放行）→ new AP4_SbgpAtom(size=12, ...) → 构造函数 line 76-88
- **描述**: `Create()` 仅检查 `size >= 12`，构造函数第 76 行 `remains = size - GetHeaderSize() = 12 - 12 = 0`，随后在 line 78 无条件执行 `remains -= 4`，使 `remains` 从 `0` 下溢为 `0xFFFFFFFC`（unsigned 32-bit wraparound）；若 `version >= 1` 则再减 4，得 `0xFFFFFFF8`；再在 line 86 减 4 得 `0xFFFFFFF4`。此时 line 87 的检查 `if (0xFFFFFFF4 < entry_count*8)` 对任意 `entry_count <= 0x1FFFFFFF` 均为 false（不触发 return），使攻击者能以任意合法值的 `entry_count` 绕过边界保护，传入大值至 `SetItemCount`，导致堆内存耗尽（DoS）。此外，`stream.ReadUI32` 在 `remains=0` 时仍被调用，将越过 atom 声明边界读取流数据（越界读），可泄露 atom 外的文件字节。
- **触发条件**: 构造一个 `sbgp` box，将其 `size` 字段设为恰好等于 `AP4_FULL_ATOM_HEADER_SIZE`（12 字节），`entry_count` 设为较大值（如 `0x1FFFFFFF`），使 `entry_count * 8 = 0xFFFFFFF8 <= remains_underflowed`，触发 DoS 或（结合 VULN-1 中的 entry_count 溢出）堆越界写。
- **安全影响**: 进程因尝试分配数 GB 内存而崩溃（DoS）；结合上一漏洞在 32 位构建中可升级为堆缓冲区溢出（RCE）。即使在 64 位构建中，由于所有流读取越过 atom 边界，还存在越界读（信息泄露）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
