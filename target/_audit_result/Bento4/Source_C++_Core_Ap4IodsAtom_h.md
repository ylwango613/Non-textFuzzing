I now have full context. Let me write the final audit report.

## VULN: AP4_DecoderConfigDescriptor SubStream Integer Underflow (payload_size < 13)
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)
- **行号**: 92 (Ap4DecoderConfigDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow → Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File(stream)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_IodsAtom::Create` → `AP4_IodsAtom(size,version,flags,stream)` → `AP4_DescriptorFactory::CreateDescriptorFromStream(stream, descriptor)` → `new AP4_ObjectDescriptor/AP4_InitialObjectDescriptor(stream, tag, header_size, payload_size)` → [OD SubStream] → `AP4_DescriptorFactory::CreateDescriptorFromStream(*substream, descriptor)` → `new AP4_EsDescriptor(substream, header_size, payload_size)` → [ES SubStream] → `AP4_DescriptorFactory::CreateDescriptorFromStream(*es_substream, descriptor)` → `new AP4_DecoderConfigDescriptor(es_substream, header_size, payload_size)` → `AP4_SubStream(es_substream, start+13, payload_size-13)` **[UNDERFLOW]**
- **描述**: `AP4_DecoderConfigDescriptor` 的流式构造函数在读取 13 字节固定字段（OTI 1字节 + bits 1字节 + BufferSize 3字节 + MaxBitrate 4字节 + AvgBitrate 4字节）后，直接计算 `payload_size - 13`（Ap4DecoderConfigDescriptor.cpp:92）。`payload_size` 和 `13` 均为 `AP4_UI32` 无符号类型，当攻击者将该 descriptor 的 payload_size 设为 0–12 时，无符号减法下溢，结果为 `0xFFFFFFF3`–`0xFFFFFFFF`（约 4.3 GB）。该值零扩展为 `AP4_LargeSize`（64位）后传给 `AP4_SubStream` 构造函数，创建出 m_Size≈4.3GB 的子流。此后 `CreateDescriptorFromStream` 循环在该失控子流内解析子描述符，读取超出 DecoderConfigDescriptor 声明边界的文件字节，将相邻字节误解析为 DecoderSpecificInfo 描述符（攻击者控制）；若子描述符声明了巨大 payload_size（最大 268MB），`SetDataSize` 将申请该大小堆块，而 `stream.Read` 返回值未被检查，导致堆块仅部分填充，其余为未初始化堆内存。
- **触发条件**: 攻击者构造如下 iods box 层级：`iods → IOD/OD descriptor → EsDescriptor → DecoderConfigDescriptor(payload_size = 0)`，DecoderConfig payload 声明为 0 字节，后接一个 `DECODER_SPECIFIC_INFO`（tag=0x05）描述符，其 payload_size 可设为 0x0FFFFFFF（最大合法编码值）。整个 iods box 在合法的 moov 容器内，mp42aac 初始化时即触发完整解析路径。
- **安全影响**: (1) DoS / OOM：DecoderSpecificInfo 的 `SetDataSize(payload_size)` 尝试分配最多 268MB 堆块，可导致 `std::bad_alloc` 或 OOM 崩溃；(2) 信息泄露：大堆块通过 `stream.Read` 仅部分填充，剩余为未初始化堆内存，若后续 `WriteFields` 或 `Inspect` 将整个 `GetDataSize()` 字节写入输出，可泄露 heap layout；(3) OOB 读：子流误解析超越 DecoderConfig 声明边界的相邻 iods 数据，可能触发后续描述符解析器崩溃。

## VULN: AP4_ObjectDescriptor SubStream Integer Underflow (payload_size < consumed_bytes)
- **漏洞类别**: memory-safety
- **函数**: AP4_ObjectDescriptor::AP4_ObjectDescriptor(AP4_ByteStream&, AP4_UI08, AP4_Size, AP4_Size)
- **行号**: 95-96 (Ap4ObjectDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow → Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File(stream)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_IodsAtom::Create` → `AP4_IodsAtom(size,version,flags,stream)` → `AP4_DescriptorFactory::CreateDescriptorFromStream(stream, descriptor)` → `new AP4_ObjectDescriptor(stream, tag, header_size, payload_size=0)` → 构造函数 `ReadUI16(bits)` 读取 2 字节后，`AP4_SubStream(stream, offset, payload_size - AP4_Size(offset-start))` = `AP4_SubStream(stream, offset, 0 - 2)` **[UNDERFLOW]**
- **描述**: `AP4_ObjectDescriptor` 的流式构造函数（Ap4ObjectDescriptor.cpp:95-96）在读取 2 字节（`ReadUI16(bits)`）后，计算 `payload_size - AP4_Size(offset-start)`（均为 `AP4_Size` = `AP4_UI32` 无符号类型）来创建子流。当攻击者将描述符的 payload_size 编码为 0（`0x00` 字节）时，`offset-start = 2`，无符号减法 `0 - 2 = 0xFFFFFFFE`（约 4.3 GB），被传给 `AP4_SubStream` 作为 m_Size，使子流大小失控。当 `m_UrlFlag` 为真时消耗更多字节（ReadUI08 + url_length 字节），触发窗口更大（payload_size < 3+url_length）。`AP4_InitialObjectDescriptor` 中相同模式出现在 Ap4ObjectDescriptor.cpp:254-255，url_flag 为假时读取 7 字节，payload_size < 7 即触发。
- **触发条件**: 攻击者在 moov/iods box 中放置 ObjectDescriptor（tag=0x01/0x11），将其 payload_size 编码为 0（MPEG-4 expandable class size 第一字节为 0x00）；此时构造函数读取的 2 字节超过声明的 0 字节边界，`payload_size - (offset-start) = 0xFFFFFFFE`。
- **安全影响**: 失控子流（m_Size≈4.3GB）绕过 SubStream 的边界检查，从 iods 数据区域中超越声明的 ObjectDescriptor 边界持续读取，将后续字节误解析为子描述符（EsIdIncDescriptor / EsDescriptor 等），可导致：大量堆分配（攻击者可在文件后续字节填写巨大 payload_size）；OOB 读造成崩溃；未初始化堆内存泄露。

## VULN: AP4_EsDescriptor SubStream Integer Underflow (payload_size < 3)
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)
- **行号**: 102-103 (Ap4EsDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow → Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File(stream)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_IodsAtom::Create` → `AP4_IodsAtom(size,version,flags,stream)` → `AP4_DescriptorFactory::CreateDescriptorFromStream(stream, descriptor)` → `new AP4_ObjectDescriptor(stream, tag, header_size, payload_size)` → [OD SubStream] → `AP4_DescriptorFactory::CreateDescriptorFromStream(*substream, descriptor)` → `new AP4_EsDescriptor(substream, header_size, payload_size=0)` → 构造函数读取 `ReadUI16(EsId)` + `ReadUI08(flags)` = 3 字节后，`AP4_SubStream(substream, offset, 0 - 3)` = `AP4_SubStream(substream, offset, 0xFFFFFFFD)` **[UNDERFLOW]**
- **描述**: `AP4_EsDescriptor` 的流式构造函数（Ap4EsDescriptor.cpp:102-103）在无条件读取 `ReadUI16(m_EsId)`（2字节）+ `ReadUI08(bits)`（1字节）= 3字节后，计算 `payload_size - AP4_Size(offset-start)` 来创建子流。两个操作数均为 `AP4_UI32` 无符号类型。当攻击者将 EsDescriptor 的 payload_size 编码为 0 或 1 或 2（均 < 3），无符号减法下溢分别得到 `0xFFFFFFFD`、`0xFFFFFFFE`、`0xFFFFFFFF`，这些值作为 `AP4_LargeSize`（64位）传给 `AP4_SubStream`，使子流大小膨胀至约 4.3GB。若还设置了 `AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY`（读取 2 字节），或 `AP4_ES_DESCRIPTOR_FLAG_URL`（读取 url_length+1 字节），则触发下溢的 payload_size 阈值更高。此外，EsDescriptor 第 93 行存在逻辑错误（`if (m_Flags & AP4_ES_DESCRIPTOR_FLAG_URL)` 误读 OcrEsId），在 URL flag 置位时额外消耗 2 字节，进一步扩大可触发下溢的 payload_size 范围。
- **触发条件**: 攻击者在 iods OD 层内放置 EsDescriptor（tag=0x03），payload_size 编码为 2（MPEG-4 expandable class size 字节 `0x02`）；构造函数读取 3 字节后 `offset-start = 3 > payload_size = 2`，`2 - 3 = 0xFFFFFFFF`。
- **安全影响**: 失控 EsDescriptor 子流（m_Size≈4.3GB）将相邻 iods/moov 数据解析为 DecoderConfigDescriptor / DecoderSpecificInfoDescriptor，攻击者可通过填写大 payload_size 触发 `SetDataSize` 的巨量堆分配（最大 268MB），导致 OOM 崩溃（DoS）；同时 `stream.Read` 返回值在 DecoderSpecificInfoDescriptor 构造函数中未检查，造成已分配大堆块仅部分初始化，其余为 uninitialized heap 内容，可导致信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
