Now I have sufficient context. Let me compile the findings.

**Summary of analysis pass:**

- `Ap4EsdsAtom.cpp`: thin wrapper; delegates to `AP4_DescriptorFactory::CreateDescriptorFromStream`
- `Ap4DescriptorFactory.cpp` L66-78: variable-length size encoding capped at 28 bits (max `0x0FFFFFFF`); then dispatches into typed descriptor constructors
- `Ap4DecoderConfigDescriptor.cpp` L92: `AP4_SubStream(stream, start+13, payload_size-13)` — both operands `AP4_Size` = `uint32_t`; if `payload_size < 13`, unsigned underflow to ~4 GB
- `Ap4EsDescriptor.cpp` L102-103: `payload_size - AP4_Size(offset-start)` — same underflow pattern when consumed bytes > `payload_size`
- `Ap4ObjectDescriptor.cpp` L96: identical pattern
- `Ap4ByteStream.cpp` L446: SubStream `ReadPartial` clamps reads against `m_Size` (`AP4_LargeSize` = uint64); the underflowed ~4 GB value is stored as uint64 = 0xFFFF…, so clamping never triggers → descriptor factory reads far beyond the intended atom boundary
- `Ap4DecoderSpecificInfoDescriptor.cpp` L63-64: allocates buffer of `payload_size` and reads into it — the "phantom" descriptor parsed from out-of-bounds file bytes can carry an attacker-chosen `payload_size` (up to 0x0FFFFFFF ≈ 256 MB)
- `Ap4DataBuffer.cpp` L191-196: `existing_size + data_size` integer overflow in `AppendData` — not reachable via esds/descriptor path in mp42aac audio flow
- `Ap4DecoderSpecificInfoDescriptor::Inspect` multiplication: `GetDataSize()*3` — max `0x0FFFFFFF * 3 = 0x2FFFFFFD`, no 32-bit wraparound; Inspect not called in mp42aac normal flow

## VULN: Integer Underflow in AP4_DecoderConfigDescriptor Creates Out-of-Bounds SubStream
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()
- **行号**: 92 (Ap4DecoderConfigDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow leading to CWE-125 Out-of-Bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → box parsing → AP4_EsdsAtom::Create() → AP4_DescriptorFactory::CreateDescriptorFromStream() (tag=DECODER_CONFIG) → new AP4_DecoderConfigDescriptor(stream, header_size, payload_size) → line 92: `new AP4_SubStream(stream, start+13, payload_size-13)`
- **描述**: `payload_size` 是从 esds box 字节流中 7-bit 可变长度编码解析得到的 `AP4_UI32`（无符号 32 位），攻击者可将其设为任意值（0–0x0FFFFFFF）。构造函数在 lines 82–89 先从流中固定读取 13 字节字段（OTI 1B + bits 1B + BufferSize 3B + MaxBitrate 4B + AvgBitrate 4B），然后在 line 92 计算 `payload_size - 13`。当攻击者设 `payload_size < 13`（如 0），该减法为无符号 32 位整数下溢，结果约为 `0xFFFFFFF3`（≈4 GB），被零扩展后赋给 `AP4_SubStream::m_Size`（`AP4_LargeSize` = uint64）。`ReadPartial` 的边界校验 `m_Position + bytes_to_read > m_Size` 永远不会裁剪，SubStream 可无限从容器流中读取，跨越 DecoderConfig 描述符边界，读取后续文件数据并将其解析为子描述符。若攻击者精心布局文件使"越界"数据形如一个 DecoderSpecificInfo 描述符（tag=0x05）且 `payload_size = 0x0FFFFFFF`，则 `AP4_DecoderSpecificInfoDescriptor` 会调用 `m_Info.SetDataSize(0x0FFFFFFF)` 分配 ≈256 MB 堆缓冲区，再以 `stream.Read(m_Info.UseData(), 0x0FFFFFFF)` 将后续文件内容填入其中；当文件较小时此次巨额分配或导致进程因 `std::bad_alloc` 崩溃（DoS）。
- **触发条件**: 在 MP4 文件的 `moov/trak/mdia/minf/stbl/stsd/mp4a/esds` 中构造 ES_Descriptor，其内嵌 DecoderConfig 子描述符并将该描述符的 `payload_size` 字段编码为小于 13 的值（如 0x00），同时在描述符边界之后布置形似 DecoderSpecificInfo 描述符（tag=0x05 + 大 payload_size）的字节序列。
- **安全影响**: 最坏情况为 DoS（进程因 OOM 崩溃）；另可导致 out-of-bounds 读取文件内容（攻击者控制范围内的数据）被当作描述符载荷处理，潜在影响后续业务逻辑（如将错误 ASC 写入输出 .aac 文件）。

## VULN: Integer Underflow in AP4_EsDescriptor Creates Out-of-Bounds SubStream
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor()
- **行号**: 102-103 (Ap4EsDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow leading to CWE-125 Out-of-Bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → box parsing → AP4_EsdsAtom::Create() → AP4_DescriptorFactory::CreateDescriptorFromStream() (tag=ES) → new AP4_EsDescriptor(stream, header_size, payload_size) → line 102-103: `new AP4_SubStream(stream, offset, payload_size-AP4_Size(offset-start))`
- **描述**: `AP4_EsDescriptor` 构造函数先在流中记录起始位置 `start`（line 66），然后读取多个固定/条件字段：`es_id`（2 B）、`bits`（1 B）；若 STREAM_DEPENDENCY 标志置位再读 2 B（`m_DependsOn`）；若 URL 标志置位再读 1 B（url_length）+ url_length B + 2 B（OcrEsId）。之后在 line 101 再次 Tell() 得到 `offset`，计算 `payload_size - AP4_Size(offset - start)`（二者均为 `AP4_UI32`）。当 `payload_size` 被攻击者设为小于已消费字节数时（最低情形：无标志位时消费 3 B，`payload_size` < 3 即触发），无符号减法下溢结果约 4 GB，传入 `AP4_SubStream` 构造函数后被零扩展为 `AP4_LargeSize`（uint64），SubStream 边界失效。后续的 `AP4_DescriptorFactory::CreateDescriptorFromStream` 循环（lines 105-109）可从 ES 描述符边界之外的文件数据中无限读取并解析子描述符，导致越界读和可能的巨额堆分配（同上述 DecoderConfig 场景）。
- **触发条件**: 在 `esds` 中构造 ES_Descriptor，将其 `payload_size` 编码为小于实际最少字段消耗的值（如设 `payload_size = 2`，同时在 bits 字段中将 STREAM_DEPENDENCY 或 URL 标志置位以增大消耗字节数超过 payload_size）；在 ES_Descriptor 边界之后的文件区域布置形似大 payload_size 的子描述符字节序列。
- **安全影响**: DoS（OOM 崩溃）；越界读取文件后续区域内容，该内容被当作合法描述符载荷处理，影响程序行为（错误的 DecoderSpecificInfo 被返回给 mp42aac 并写入输出文件）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
