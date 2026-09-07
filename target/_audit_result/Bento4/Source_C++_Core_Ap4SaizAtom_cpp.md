Now I have all the context needed. Let me analyze the complete vulnerability chain.

**Analysis of `Ap4SaizAtom.cpp` constructor (lines 70–103):**

```
AP4_UI32 remains = size - GetHeaderSize();   // (1) size >= 12 guaranteed; remains >= 0
if (flags & 1) {
    stream.ReadUI32(m_AuxInfoType);
    stream.ReadUI32(m_AuxInfoTypeParameter);
    remains -= 8;                             // (2) AP4_UI32 underflow if remains < 8
}
stream.ReadUI08(m_DefaultSampleInfoSize);
stream.ReadUI32(m_SampleCount);
remains -= 5;                                // (3) AP4_UI32 underflow if remains < 5
if (m_DefaultSampleInfoSize == 0) {
    if (m_SampleCount > remains) m_SampleCount = remains;   // (4) sanity check uses underflowed `remains`
    AP4_Cardinal sample_count = m_SampleCount;
    m_Entries.SetItemCount(sample_count);    // (5) return value NOT checked
    unsigned char* buffer = new AP4_UI08[sample_count];   // (6) massive allocation
```

**Underflow path:** `Create()` only checks `size >= AP4_FULL_ATOM_HEADER_SIZE (12)`, so a crafted box with:
- `size = 12`, `flags = 1 (bit 0 set)` → `remains = 0`, `remains -= 8` → **`remains = 0xFFFFFFF8`** (AP4_UI32 underflow)
- Then `remains -= 5` → **`remains = 0xFFFFFFF3`**

The sanity check at (4) then compares `m_SampleCount > 0xFFFFFFF3`, which is true only for values > ~4 billion. Any attacker-supplied `m_SampleCount` ≤ 4GB passes unchecked, and `new AP4_UI08[sample_count]` at (6) throws `std::bad_alloc`, crashing the process.

Similarly, `flags = 0`, `size = 16` → `remains = 4`, `remains -= 5` → **`remains = 0xFFFFFFFF`**, making the sanity check completely ineffective for any 32-bit value.

## VULN: Integer Underflow in saiz-box `remains` Bypasses Sample Count Sanity Check → Uncontrolled Heap Allocation (DoS)
- **漏洞类别**: memory-safety
- **函数**: AP4_SaizAtom::AP4_SaizAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-102
- **CWE**: CWE-191 (Integer Underflow) / CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_SaizAtom::Create() → new AP4_SaizAtom(size=12, version=0, flags=1, stream) → constructor: `remains=0`, `remains -= 8` → AP4_UI32 underflow → sanity check `if (m_SampleCount > 0xFFFFFFF3)` ineffective → `new AP4_UI08[m_SampleCount]` with attacker-controlled huge count
- **描述**: 构造函数中 `remains` 是 AP4_UI32 类型，在 `flags & 1` 分支中执行 `remains -= 8` 时若 `remains < 8` 会发生无符号整数下溢（wraps to ~4GB），随后 `remains -= 5` 再次下溢，导致 `remains ≈ 0xFFFFFFF3`。之后的安全检查 `if (m_SampleCount > remains)` 使用已下溢的巨大值，无法有效限制来自文件的 `m_SampleCount`。Create() 仅检查 `size >= AP4_FULL_ATOM_HEADER_SIZE (12)`，不阻止触发路径。攻击者可设置 `size=12, flags=1, SampleCount=0x7FFFFFFF`，使得 `new AP4_UI08[0x7FFFFFFF]` 尝试分配 2GB 堆内存，抛出 `std::bad_alloc` 崩溃进程。
- **触发条件**: 构造一个 MP4 文件，其中包含 `saiz` box，设置：box size = 12（仅 full-atom 头，无 payload），flags 字节设置 bit 0 = 1（表示 AuxInfoType 字段存在），default_sample_info_size = 0，sample_count 字段设为任意大值（如 0x7FFFFFFF）。文件其余部分为占位数据。
- **安全影响**: 攻击者可通过传入恶意 MP4 文件使 mp42aac 进程因未捕获的 std::bad_alloc 崩溃，造成可靠的拒绝服务（DoS）。若该库被集成于处理用户上传文件的网络服务中，则可远程触发服务崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
