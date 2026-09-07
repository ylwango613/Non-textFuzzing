Analysis complete. I now have the full picture:

- `Create()` only checks `size >= AP4_FULL_ATOM_HEADER_SIZE = 12`.
- Constructor computes `remains = size - GetHeaderSize()` (12), then unconditionally does `remains -= 5`.
- When `size` is between 12 and 16, `remains` is 0–4 before the subtraction, causing **unsigned integer underflow** to ~`0xFFFFFFFB`.
- The sanity check `if (m_SampleCount > remains)` is then only true if `m_SampleCount >= 0xFFFFFFFC`, so the attacker-controlled `m_SampleCount` (e.g. `0x40000000` = 1 billion) is **not clamped**.
- Both `m_Entries.SetItemCount(sample_count)` and `new AP4_UI08[sample_count]` attempt to allocate billions of bytes → OOM/`std::bad_alloc` crash.

## VULN: Integer Underflow in `remains` Bypasses Sanity Check → Uncontrolled Large Allocation (DoS)
- **漏洞类别**: memory-safety
- **函数**: AP4_SaizAtom::AP4_SaizAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-102
- **CWE**: CWE-191 (Integer Underflow leading to CWE-789 Uncontrolled Memory Allocation)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File::AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_SaizAtom::Create(size=12, stream) → AP4_SaizAtom::AP4_SaizAtom(size=12, ...) → `remains = 12-12 = 0` → `remains -= 5` → underflow to 0xFFFFFFFB → sanity check bypassed → `m_Entries.SetItemCount(attacker_count)` + `new AP4_UI08[attacker_count]`
- **描述**: 在解析 `saiz` full-atom 时，`remains` 被初始化为 `size - GetHeaderSize()`（均为 `AP4_UI32`）。`Create()` 仅校验 `size >= AP4_FULL_ATOM_HEADER_SIZE (12)`，因此 `size = 12` 合法通过，此时 `remains = 0`。随后无条件执行 `remains -= 5`（读取 `m_DefaultSampleInfoSize` 和 `m_SampleCount` 共 5 字节），`AP4_UI32` 减法下溢至 `0xFFFFFFFB`。用于防护的唯一上界校验 `if (m_SampleCount > remains)` 因 `remains` 下溢为天文数字而对几乎所有攻击者控制的 `m_SampleCount` 值失效，随后 `m_Entries.SetItemCount(sample_count)` 和 `new AP4_UI08[sample_count]` 均尝试分配攻击者指定大小的内存，导致 `std::bad_alloc` 异常使进程崩溃。
- **触发条件**: 构造一个 `saiz` box，box header 中 `size` 字段设为 12（或 13–16），`default_sample_info_size` 设为 0，`sample_count` 字段设为大数（如 `0x40000000`）。
- **安全影响**: 进程因 `std::bad_alloc` 或 OOM killer 终止，造成可远程触发的拒绝服务（DoS/crash）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
