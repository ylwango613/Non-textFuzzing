I now have sufficient context to do the complete analysis. Let me synthesize the findings:

**Analysis of `Ap4IkmsAtom.cpp` parsing constructor (lines 71-93):**

```cpp
AP4_Size string_size = size - AP4_FULL_ATOM_HEADER_SIZE;   // size - 12, AP4_UI32
if (m_Version == 1 && string_size >= 8) {
    string_size -= 8;
    stream.ReadUI32(m_KmsId);
    stream.ReadUI32(m_KmsVersion);
} else { ... }
if (string_size) {
    char* str = new char[string_size];   // NO upper-bound check
    stream.Read(str, string_size);
    str[string_size-1] = '\0';
    m_KmsUri = str;
    delete[] str;
}
```

**`Create()` guard (lines 43-52):** Only checks `size < AP4_FULL_ATOM_HEADER_SIZE` (= 12). No upper bound.

**Type chain:** `AP4_Size` = `AP4_UI32` (uint32_t). If attacker sets the iKMS atom size field = 0xFFFFFFFF, then `string_size = 0xFFFFFFFF - 12 = 0xFFFFFFF3` (~4 GB). `new char[0xFFFFFFF3]` → `std::bad_alloc` → uncaught exception → process crash (DoS). On 64-bit systems the size_t extension does not wrap; on 32-bit systems the allocation still fails.

**`WriteFields` unsigned underflow (secondary, write path):** If an iKMS atom with version=1 was parsed but `string_size < 8`, then in `WriteFields`: `padding = m_Size32 - (12 + GetLength() + 1)` followed by `padding -= 8` → unsigned underflow → infinite write loop. This path is not in the `mp42aac` attack surface (tool only reads, never rewrites iKMS atoms), so not separately reported.

## VULN: Unchecked Large Heap Allocation via File-Controlled iKMS Atom Size
- **漏洞类别**: memory-safety
- **函数**: AP4_IkmsAtom::AP4_IkmsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 77-92 (Ap4IkmsAtom.cpp)
- **CWE**: CWE-789 (Memory Allocation with Excessive Size Value)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream → AP4_IkmsAtom::Create(size_32=0xFFFFFFFF, stream) → AP4_IkmsAtom::AP4_IkmsAtom(size=0xFFFFFFFF, ...) → string_size = 0xFFFFFFFF - 12 = 0xFFFFFFF3 → new char[0xFFFFFFF3]
- **描述**: 在 `AP4_IkmsAtom` 的流式解析构造函数中，`string_size` 直接由攻击者控制的 MP4 文件中 iKMS atom 的 size 字段（`AP4_UI32`）减去固定头长度（12）计算得出，最大可达 0xFFFFFFF3（约 4 GB）。`Create()` 中仅对下界（`size < 12`）做了检查，没有任何上界校验。随后直接调用 `new char[string_size]` 尝试分配攻击者指定大小的堆内存，当分配量超出系统可用内存时，`operator new[]` 抛出 `std::bad_alloc` 异常，由于调用栈上无任何 `try/catch`，异常传播至 `std::terminate()`，导致进程崩溃。
- **触发条件**: 构造一个包含 iKMS atom（位于 moov/trak/mdia/minf/stbl/stsd/... 下的 schi box 内）且该 atom 的 4 字节 size 字段值为 0xFFFFFFFF（或任何超过系统可用内存的大值）的 MP4 文件，以命令行方式传入 `mp42aac`。
- **安全影响**: 进程以 `std::terminate()` 崩溃，实现可靠的拒绝服务（DoS）。在嵌入该库的媒体服务器场景下，远程攻击者可通过上传恶意 MP4 文件反复触发服务崩溃，造成持续不可用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
