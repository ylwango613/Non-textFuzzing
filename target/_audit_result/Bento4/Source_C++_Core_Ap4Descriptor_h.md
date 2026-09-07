Now I have sufficient context to complete the analysis. Let me compile the findings.

**Analysis Summary:**

**Batch 1 (Ap4Descriptor.h, 133 lines):** The header itself is clean — `AP4_Descriptor`, `AP4_UnknownDescriptor`, `AP4_DescriptorFinder`, `AP4_DescriptorListWriter`, `AP4_DescriptorListInspector` are wrappers with no numeric manipulation.

**Batch 2 (Ap4Descriptor.cpp):** `AP4_UnknownDescriptor` constructor calls `m_Data.SetDataSize(payload_size)` then `stream.Read(m_Data.UseData(), payload_size)` — `payload_size` ≤ 0x0FFFFFFF (capped by 4-byte MPEG-4 expandable encoding), so no 32-bit overflow, and reads are stream-bounded.

**Batch 3 (Ap4DescriptorFactory.cpp):** `payload_size` accumulation via shifting is capped at 28 bits (max 0x0FFFFFFF). After creating each descriptor, `stream.Seek(offset+header_size+payload_size)` is called — seek failures silently ignored but not a heap-corruption path.

**Batch 4 (Ap4DataBuffer.cpp):** `AppendData` has an `existing_size + data_size` integer overflow path → heap OOB write, but no descriptor code path calls `AppendData` with file-controlled sizes.

**Batch 5 (Ap4DecoderConfigDescriptor.cpp:92) — KEY FINDING:**
```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, start+13, payload_size-13);
```
`payload_size` is `AP4_UI32` (= `AP4_Size`). There is **no check that `payload_size >= 13`** before the subtraction. When a crafted file provides `payload_size < 13` for a `DecoderConfigDescriptor`, the expression `payload_size - 13` wraps to a huge unsigned value (e.g., `payload_size=5` → `0xFFFFFFF8`). This huge value becomes the SubStream's size parameter (`AP4_LargeSize`). The descriptor factory then loops reading child descriptors from far beyond the declared descriptor boundary, treating attacker-controlled adjacent bytes (from the outer ES-descriptor payload) as nested descriptor tags+sizes — triggering heap allocations of attacker-chosen sizes.

**Batch 6 (Ap4EsDescriptor.cpp:103) — KEY FINDING:**
```cpp
AP4_SubStream* substream = new AP4_SubStream(stream, offset,
                                             payload_size-AP4_Size(offset-start));
```
No guard ensures `payload_size >= (offset-start)`. With `payload_size < bytes_consumed`, `payload_size - AP4_Size(offset-start)` underflows to a near-maximal value → same category of OOB read + forced large allocation.

**Batch 7 (Ap4ObjectDescriptor.cpp:96, 255):** Same unsigned underflow pattern as EsDescriptor, in both `AP4_ObjectDescriptor` and `AP4_InitialObjectDescriptor`.

**Batch 8 (Ap4DecoderSpecificInfoDescriptor.cpp:94):** `new char[m_Info.GetDataSize()*3+1]` — with max `GetDataSize()=0x0FFFFFFF`, the product `0x2FFFFFFD` does not overflow 32-bit unsigned, and subsequent loop writes are within bounds. Not a heap corruption path.

**Batch 9 (Ap4Ipmp.cpp):** `fields_size` miscounting causes up to 16 extra bytes to be read from the stream, but bounded by parent SubStream — OOB read of bounded size, no write overflow.

## VULN: AP4_DecoderConfigDescriptor Integer Underflow → OOB Read via Oversized SubStream
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()
- **行号**: 92
- **CWE**: CWE-191 (Integer Underflow / Wraparound leading to CWE-125 Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File → moov/trak/mdia/stsd/mp4a → esds → AP4_EsdsAtom::AP4_EsdsAtom() → AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_EsDescriptor → (nested) AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor() [Ap4DecoderConfigDescriptor.cpp:92]
- **描述**: `payload_size` 来自文件中 MPEG-4 expandable-size 字段（最大 0x0FFFFFFF），在构造函数中直接执行 `payload_size - 13`（均为 AP4_UI32/AP4_Size，无符号 32 位）。当攻击者将 DecoderConfigDescriptor 的 payload_size 设为小于 13 的值（如 0、1、5）时，减法发生无符号下溢，结果为接近 0xFFFFFFFF 的巨大值，被传递给 `AP4_SubStream` 的 `size` 参数（AP4_LargeSize=uint64）。该 SubStream 以超大 size 覆盖了父 ES 描述符的实际剩余 payload，使嵌套描述符工厂循环能读取 ES payload 声明边界之外的字节，将攻击者布局的相邻字节解释为子描述符 tag+payload_size，进而触发任意大小的堆分配（最大 ~256 MB per descriptor）。
- **触发条件**: 构造 MP4 文件，使 esds 盒子中的 ES Descriptor → DecoderConfigDescriptor 的 payload_size 字段（MPEG-4 expandable 编码）设为小于 13 的值（推荐 payload_size=1，header 内置 2 字节即可），并在该描述符后紧跟任意构造的描述符 tag+size 字节序列。
- **安全影响**: 堆越界读（OOB Read）：解析器读取 DecoderConfigDescriptor 声明边界之外的任意文件字节作为嵌套描述符，导致：(1) 信息泄露——相邻堆内容以描述符形式被读取；(2) DoS——攻击者可嵌入合法 payload_size 接近 0x0FFFFFFF 的子描述符 tag，迫使 `new AP4_Byte[~256MB]` 导致 OOM（std::bad_alloc 未捕获则进程终止）；(3) 在父 SubStream 允许的范围内，可进一步链式触发其他描述符的解析路径。

## VULN: AP4_EsDescriptor Integer Underflow → OOB Read via Oversized SubStream
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor()
- **行号**: 103
- **CWE**: CWE-191 (Integer Underflow / Wraparound leading to CWE-125 Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File → moov/trak/mdia/stsd/mp4a → esds → AP4_EsdsAtom::AP4_EsdsAtom() → AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_EsDescriptor::AP4_EsDescriptor() [Ap4EsDescriptor.cpp:103]
- **描述**: 在 `AP4_EsDescriptor` 构造函数中，读取完 EsId（2字节）、flags（1字节）及可选的 DependsOn（2字节）/ URL（变长）/ OcrEsId（2字节）后，执行 `payload_size - AP4_Size(offset - start)` 来计算剩余 payload 大小（AP4_UI32 无符号减法）。当 payload_size 小于已消耗的字节数（offset-start）时，减法下溢产生接近 0xFFFFFFFF 的巨大值，以此为 size 创建 SubStream。所有子描述符（DecoderConfigDescriptor、DecoderSpecificInfoDescriptor 等）均从该超大 SubStream 中读取，可突破 ES Descriptor 的声明 payload 边界，读取文件中相邻的任意字节并将其解释为子描述符，触发后续的大规模堆分配。
- **触发条件**: 构造 MP4 文件，使 esds 盒子的 ES Descriptor payload_size 为极小值（如 0 或 1），同时在文件中 ES Descriptor 声明边界之后布置精心构造的描述符字节（tag=0x04/0x05 + 大 payload_size 的 expandable-size 编码），以触发 OOM 分配。若设置 AP4_ES_DESCRIPTOR_FLAG_URL 等 flag 位，可使 offset-start 进一步增大，加剧下溢。
- **安全影响**: 堆越界读（OOB Read）：解析器读取 ES Descriptor payload 声明范围外的文件字节，导致：(1) 相邻 MP4 box 数据以描述符形式被解析，造成信息泄露；(2) 通过在边界外放置大 payload_size 的伪造子描述符，强制执行 `new AP4_Byte[~256MB]` 级别的分配，造成 DoS（OOM / 进程终止）；(3) 在已有 SubStream 层级保护下，读取深度受文件实际数据量约束，但攻击者完全控制文件内容，可最大化越界读取范围。

<!-- AUDIT_PROMPT_VERSION: 1 -->
