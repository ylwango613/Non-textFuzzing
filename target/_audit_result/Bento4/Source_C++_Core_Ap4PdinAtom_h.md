Now I have enough context to complete the analysis. Let me summarize the findings:

**Ap4PdinAtom.cpp constructor analysis (lines 74–86):**

- `size` arrives from the MP4 file's box size field (AP4_UI32); only guarded by `size < AP4_FULL_ATOM_HEADER_SIZE (12)` — no upper bound.
- `entry_count = (size - 12) / 8` can be up to `(0xFFFFFFFF - 12)/8 = 536,870,910`.
- `m_Entries.SetItemCount(entry_count)` → `EnsureCapacity(536870910)` → `::operator new(536870910 * 8 ≈ 4 GB)`.
- The return value of `SetItemCount` at line 81 is **not checked**.
- When the allocator cannot service ~4 GB and returns `AP4_ERROR_OUT_OF_MEMORY` (NULL-return path checked at Ap4Array.h:173), `m_Entries.m_Items` stays `nullptr` and `m_ItemCount` stays 0.
- The loop at lines 82–85 then executes `entry_count` iterations accessing `m_Entries[i]` → `m_Items[i]` with `m_Items == nullptr` → **NULL-pointer dereference / crash**.

Even in the throwing-allocator path the unguarded 4 GB allocation triggers an unhandled `std::bad_alloc` that crashes the parser — a reliable DoS from a single crafted `pdin` box.

## VULN: Unchecked OOM in AP4_PdinAtom constructor leads to NULL-ptr dereference
- **漏洞类别**: memory-safety
- **函数**: AP4_PdinAtom::AP4_PdinAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 80-85 (Ap4PdinAtom.cpp)
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_PdinAtom::Create(size_32, stream) → new AP4_PdinAtom(size, version, flags, stream) → constructor line 81: m_Entries.SetItemCount(entry_count) [return ignored] → EnsureCapacity: ::operator new(~4GB) returns NULL → SetItemCount returns AP4_ERROR_OUT_OF_MEMORY (unchecked) → loop lines 82-85: m_Entries[i] dereferences m_Items == nullptr
- **描述**: `pdin` box 的 `size` 字段直接来自文件，仅检查下界（>=12），无上界校验。当 size≈0xFFFFFFFF 时，`entry_count=(size-12)/8≈536870910`。`SetItemCount(entry_count)` 调用 `EnsureCapacity`，后者使用标准 `::operator new` 申请约 4 GB 内存；当分配器无法满足时（NULL 返回路径，见 Ap4Array.h:173），EnsureCapacity 返回 AP4_ERROR_OUT_OF_MEMORY，而 SetItemCount 的返回值在构造函数第 81 行被完全忽略，导致 m_Entries.m_Items 仍为 nullptr、m_ItemCount 仍为 0，随后第 82–85 行的循环对 m_Entries[i]（即 nullptr[i]）执行解引用，触发内存安全违规（NULL 指针解引用）。即使在抛出异常的分配器实现中，未处理的 std::bad_alloc 同样导致进程崩溃。
- **触发条件**: 构造一个 `pdin` box，将其 size 字段设置为 0xFFFFFFFF（或任何满足 (size-12)/8 * sizeof(Entry) 超出系统可用内存的大值），嵌入 MP4 文件的 moov 容器中。mp42aac 解析该文件时会进入 AP4_PdinAtom 构造函数并触发漏洞。
- **安全影响**: 攻击者向 mp42aac 传入精心构造的 MP4 文件可稳定触发进程崩溃（DoS）。在 NULL 返回型分配器环境中，可进一步导致 NULL 指针解引用，属于内存安全违规，理论上在极特殊的内存布局下可被利用；在主流平台上主要后果为可靠的应用级 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
