Now I have a complete picture of all the relevant code. Let me compile my findings.

**Batch 1 (lines 1–500) analysis:**
- `AP4_SampleEntry::Read` (lines 104–117): `payload_size` bounded by atom size (already validated against stream size in AtomFactory). Safe.
- `AP4_UnknownSampleEntry` constructor (lines 238–247): `size` bounded by `bytes_available` check at AtomFactory line 215. Safe.
- `AP4_AudioSampleEntry::ReadFields` (lines 468–524): **CRITICAL finding at lines 500–503** — `m_QtV2StructSize` is read from file as `AP4_UI32` (line 492) with no bound check against the remaining box size. `ext_size = m_QtV2StructSize - 72` can reach `0xFFFFFFB7 ≈ 4.3 GB`. `SetDataSize(ext_size)` return value is **ignored**, then `ReallocateBuffer(ext_size)` calls `new AP4_Byte[0xFFFFFFB7]` (non-nothrow form) → throws `std::bad_alloc` → unhandled → process terminates.

**Batch 2 (lines 500–900) analysis:**
- `AP4_VisualSampleEntry::ReadFields` compressor_name parsing (lines 775–782): `compressor_name[33]`, read 32 bytes, `name_length < 32` guard ensures `compressor_name[name_length+1]` writes to index ≤ 32. Safe.

**Batch 3 (lines 900–1272) analysis:**
- `AP4_SubtitleSampleEntry::ReadFields` (lines 1197–1211): `ReadNullTerminatedString` loops byte-by-byte calling `SetDataSize(size+1)` without doubling (triggers O(n²) reallocations), but stream bounded by file size — DoS via CPU only, not memory safety.
- `AP4_RtpHintSampleEntry::ReadFields`: all reads bounded. Safe.

**AtomFactory bound check (line 215 of Ap4AtomFactory.cpp):**
Box `size` header IS validated: `if (size > bytes_available) return AP4_ERROR_INVALID_FORMAT`. This bounds the outer box size, but does NOT bound internal fields like `m_QtV2StructSize`, which is inside the box payload.

**Confirmed vulnerability:**
`m_QtV2StructSize` set to `0xFFFFFFFF` inside a minimal valid `mp4a` box (≥ 40 bytes) triggers `new AP4_Byte[0xFFFFFFB7]` → `std::bad_alloc` → crash. The ignored return value of `SetDataSize` at line 502 is a secondary code quality defect, but the primary crash path is the unguarded huge `new`.

---

## VULN: Uncontrolled Heap Allocation via Attacker-Controlled QtV2StructSize in Audio Sample Entry
- **漏洞类别**: memory-safety
- **函数**: AP4_AudioSampleEntry::ReadFields()
- **行号**: 492-503
- **CWE**: CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → ParseAtoms() → AP4_AtomFactory::CreateAtomFromStream() → new AP4_Mp4aSampleEntry(size_32, stream, *this) → AP4_AudioSampleEntry::AP4_AudioSampleEntry() → Read() → ReadFields() → SetDataSize(ext_size) → ReallocateBuffer(0xFFFFFFB7) → new AP4_Byte[0xFFFFFFB7] → std::bad_alloc (unhandled) → process termination
- **描述**: 在 `AP4_AudioSampleEntry::ReadFields`（Ap4SampleEntry.cpp 第 492 行）中，从 MP4 文件读取 `m_QtV2StructSize`（AP4_UI32，4 字节，完全由攻击者控制），当 `m_QtVersion == 2` 时，第 500-503 行直接计算 `ext_size = m_QtV2StructSize - 72`，未验证该值是否超出 box 实际剩余字节数，即可将 `ext_size` 设为最大 `0xFFFFFFB7`（≈4.3 GB）。随后 `m_QtV2Extension.SetDataSize(ext_size)` 的返回值被完全忽略，该函数内部调用 `ReallocateBuffer(ext_size)` → `new AP4_Byte[ext_size]`（非 nothrow 形式）。当分配失败时抛出 `std::bad_alloc`，整个调用链（从 `mp42aac main` 到此处）均无 try/catch，导致进程因未捕获异常而终止。外层的 box 总大小合法性检查（AtomFactory.cpp 第 215 行）仅约束 box header 中声明的总字节数，无法约束 box payload 内部的 `m_QtV2StructSize` 字段。
- **触发条件**: 攻击者构造一个最小 40 字节的 `mp4a`（或任意音频类型）sample entry box：将 box payload 第 6-7 字节（m_QtVersion）设为 `0x0002`，将 payload 第 28-31 字节（m_QtV2StructSize）设为 `0xFFFFFFFF`，box 的 size 字段合法（≥40 且≤文件实际大小），以通过 AtomFactory 的合法性检查。
- **安全影响**: 可靠的程序崩溃（DoS）。进程因未捕获的 `std::bad_alloc` 异常而立即终止，攻击者可通过分发一个 40 字节左右的恶意 MP4 文件对任何调用 `mp42aac`（或任何嵌入 Bento4 库）的服务或用户造成可重复的拒绝服务攻击。

<!-- AUDIT_PROMPT_VERSION: 1 -->
