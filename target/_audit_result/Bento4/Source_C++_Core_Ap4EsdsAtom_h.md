I now have all the data needed. Let me produce the final audit report.

**Analysis summary:**

**VULN 1 — `AP4_EsDescriptor.cpp` lines 100–103** (primary, high-severity):  
`payload_size - AP4_Size(offset-start)` is a `uint32_t` subtraction. When the URL flag is set in `bits`, the constructor reads 6+ bytes (EsId=2, bits=1, url_length=1, OcrEsId=2) regardless of `payload_size`. An attacker setting `payload_size=3` with the URL flag causes `3 - 6 = 0xFFFFFFFA` (wrap). The resulting `AP4_SubStream` has `m_Size ≈ UINT32_MAX`, backed by the **raw file stream** (not bounded by the esds atom). The factory loop then parses sub-descriptors from arbitrary bytes past the esds atom boundary, treating random/attacker-controlled file bytes as descriptor tag/size values. If those bytes encode a large `payload_size`, `AP4_UnknownDescriptor` or `AP4_DecoderSpecificInfoDescriptor` will call `new AP4_Byte[payload_size]` — triggering heap exhaustion, crash, or heap-state corruption depending on values read from the file.

**VULN 2 — `Ap4DecoderConfigDescriptor.cpp` line 92** (secondary):  
`AP4_SubStream(stream, start+13, payload_size-13)` underflows when `payload_size < 13`. The overflowed SubStream's reads are, in isolation, bounded by the parent ES SubStream — but if VULN 1 already broke the parent ES SubStream's bounds, both compound to extend OOB reads through the entire file.

---

## VULN: Integer Underflow in AP4_EsDescriptor SubStream size → Heap OOB Read / Uncontrolled Allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor()
- **行号**: 100-103
- **CWE**: CWE-191 (Integer Underflow) leading to CWE-125 (Out-of-Bounds Read) / CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream → AP4_EsdsAtom::Create → AP4_DescriptorFactory::CreateDescriptorFromStream(raw_file_stream, descriptor) → new AP4_EsDescriptor(raw_file_stream, header_size, payload_size) → AP4_EsDescriptor::AP4_EsDescriptor (Ap4EsDescriptor.cpp:61) → uint32 underflow at line 102 → AP4_SubStream(raw_file_stream, offset, 0xFFFFFFFA) → factory loop reads OOB descriptors → AP4_UnknownDescriptor/AP4_DecoderSpecificInfoDescriptor allocates heap from attacker-controlled payload_size
- **描述**: 在 `AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size header_size, AP4_Size payload_size)` 中（Ap4EsDescriptor.cpp 行 100–103），当 ES descriptor 的 flags 字段中 URL bit（bit 1）被设置时，构造函数会读取 url_length（1字节）以及 OcrEsId（2字节，第二处 `if (m_Flags & AP4_ES_DESCRIPTOR_FLAG_URL)` 条件与 OCR_STREAM flag 混淆）共计至少 6 字节（EsId=2 + bits=1 + url_length=1 + OcrEsId=2）。此后计算 `payload_size - AP4_Size(offset-start)`：若攻击者将 ES descriptor 的 `payload_size` 设为 3，则该减法为 `(uint32_t)3 - 6 = 0xFFFFFFFA`，导致下溢。下溢后的值被传入 `AP4_SubStream(stream, offset, 0xFFFFFFFA)`，令该子流的 `m_Size ≈ 4 GB`。该子流的容器 stream 是**原始文件流**（非受限 SubStream），因此后续对子流的读取可越过 esds atom 的声明边界，访问 MP4 文件中任意后续字节。工厂循环 `CreateDescriptorFromStream(*substream, descriptor)` 会将这些 OOB 字节解析为描述符 tag 和 payload_size，并据此执行 `new AP4_Byte[payload_size]` 分配（在 AP4_UnknownDescriptor 或 AP4_DecoderSpecificInfoDescriptor 构造函数中），造成无控制的大量内存分配或堆状态损坏。
- **触发条件**: 构造一个 MP4 文件，其 `esds` atom 内的 ES Descriptor 头部满足：(1) payload_size 字段编码值 ≤ 5（如设为 3）；(2) ES_ID 后的 flags/priority 字节中设置 URL bit（0x40），url_length 设为 0；这使构造函数消耗 6 字节但 payload_size 只有 3，触发 uint32 下溢。之后在 esds atom 之后紧随另一 box，其前 5 字节（MPEG-4 expandable size 编码）被解析为一个大 payload_size（最大 268 MB），触发 `new AP4_Byte[large_size]`。
- **安全影响**: 越界读取 MP4 文件任意位置的字节（信息泄露）；基于文件控制字节触发超大堆分配（内存耗尽/DoS）；若 OOB 字节触发 AP4_DataBuffer::ReallocateBuffer 中未检查 new 返回值的代码路径（Ap4DataBuffer.cpp:210），可导致空指针解引用崩溃（DoS）；在可控字节条件下，理论上可进一步利用堆状态损坏实现 RCE。

## VULN: Integer Underflow in AP4_DecoderConfigDescriptor SubStream size → OOB Read within ES Descriptor Payload
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()
- **行号**: 92
- **CWE**: CWE-191 (Integer Underflow) leading to CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 6.6 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File::AP4_File → AP4_EsdsAtom::Create → AP4_EsDescriptor constructor → AP4_DescriptorFactory::CreateDescriptorFromStream(*es_substream) → new AP4_DecoderConfigDescriptor(*es_substream, header_size, payload_size) → AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor (Ap4DecoderConfigDescriptor.cpp:71) → uint32 underflow at line 92 → AP4_SubStream(*es_substream, start+13, 0xFFFFFFFF-12) → factory loop OOB reads within ES payload region
- **描述**: 在 `AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream& stream, AP4_Size header_size, AP4_Size payload_size)` 中（Ap4DecoderConfigDescriptor.cpp 行 92），代码无条件从 stream 读取 13 字节（ObjectTypeIndication=1 + bits=1 + BufferSize=3 + MaxBitrate=4 + AvgBitrate=4），然后创建子流 `new AP4_SubStream(stream, start+13, payload_size-13)`。若攻击者将 DecoderConfig descriptor 的 `payload_size` 设为小于 13 的值（如 0），则 `payload_size - 13` 在 uint32_t 下溢为 `0xFFFFFFFF - 12 ≈ 4 GB`。该过大的 SubStream 以父 ES descriptor SubStream 为容器；若父 SubStream 本身也因 VULN-1 而下溢（即父 m_Size ≈ 4 GB），则两层均不设边界，子流可读取文件中任意字节；即使父 SubStream 正常，也可在 ES payload 内越界读取。
- **触发条件**: 在 esds atom 的 ES Descriptor 内嵌入一个 DecoderConfig descriptor，将其 MPEG-4 expandable size 编码为小于 13 的值（如 0 或 5）；配合 VULN-1 使父 ES SubStream 也下溢，则两层下溢叠加，越界范围延伸至文件全域。
- **安全影响**: 越界读取 ES descriptor payload 区域外的文件字节（信息泄露）；配合 VULN-1 可读取 esds atom 以外的任意文件内容；若 OOB 字节被解析为大 payload_size，进一步触发无控制大内存分配（DoS/崩溃）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
